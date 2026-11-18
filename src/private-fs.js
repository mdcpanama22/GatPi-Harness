"use strict";
// Private-mode hardening that works on every platform Pi runs on.
//
// POSIX: fchmod the descriptor (0o700 directories, 0o600 files) as before.
// Windows: there are no group/other mode bits, and fchmod on a directory
// descriptor throws EPERM, so directories are skipped and files only get the
// read-only flag Node maps from the mode. Privacy on Windows comes from the
// user profile's ACL; files holding secrets should be checked with an ACL
// check such as windowsAclIsPrivate in src/pi-queue/config.js.
const nodeFs = require("node:fs");

function hardenFd(fd, mode, { platform = process.platform, fs = nodeFs } = {}) {
  if (platform === "win32" && fs.fstatSync(fd).isDirectory()) return;
  fs.fchmodSync(fd, mode);
}

module.exports = { hardenFd };
