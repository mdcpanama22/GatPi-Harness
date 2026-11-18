"use strict";
// hardenFd applies POSIX private modes where they exist and never breaks on Windows,
// where directories have no mode bits (fchmod on a directory fd throws EPERM).
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { hardenFd } = require("../src/private-fs.js");

const root = fs.mkdtempSync(path.join(os.tmpdir(), "harness-private-fs-"));
const dir = path.join(root, "state");
const file = path.join(dir, "state.json");
fs.mkdirSync(dir);
fs.writeFileSync(file, "{}\n");

function withFd(target, fn) {
  const fd = fs.openSync(target, "r");
  try { return fn(fd); } finally { fs.closeSync(fd); }
}

// Directory and file hardening succeed on the real platform.
withFd(dir, (fd) => hardenFd(fd, 0o700));
const fileFd = fs.openSync(file, "r+");
try { hardenFd(fileFd, 0o600); } finally { fs.closeSync(fileFd); }

if (process.platform === "win32") {
  // A file stays writable (0o600 keeps the owner write bit, so no read-only flag).
  fs.writeFileSync(file, "{\"ok\":true}\n");
  assert.equal(fs.readFileSync(file, "utf8"), "{\"ok\":true}\n");
} else {
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
}

// The platform decision is explicit: win32 skips directories and chmods files;
// POSIX always chmods.
const calls = [];
const fakeFs = {
  fstatSync: (fd) => ({ isDirectory: () => fd === "dir-fd" }),
  fchmodSync: (fd, mode) => calls.push([fd, mode]),
};
hardenFd("dir-fd", 0o700, { platform: "win32", fs: fakeFs });
hardenFd("file-fd", 0o600, { platform: "win32", fs: fakeFs });
hardenFd("dir-fd", 0o700, { platform: "linux", fs: fakeFs });
hardenFd("file-fd", 0o600, { platform: "linux", fs: fakeFs });
assert.deepEqual(calls, [["file-fd", 0o600], ["dir-fd", 0o700], ["file-fd", 0o600]]);

fs.rmSync(root, { recursive: true, force: true });
console.log("private-fs tests passed");
