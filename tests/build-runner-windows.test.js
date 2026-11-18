"use strict";
// Windows-only behaviour of build-runner and the managed-worker lock:
// cancelling a build ends its whole process tree, and worker slots are a
// cross-process lock that is freed when the holding process dies.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { runBuild } = require("../src/build-runner.js");
const { acquireManagedWorker } = require("../src/resource-guard.js");
const { tmpFixture } = require("./helpers/tmp-fixture");

if (process.platform !== "win32") {
  console.log("build-runner windows tests skipped (not Windows)");
  process.exit(0);
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };

(async () => {
  const tmp = tmpFixture("pi-build-runner-win-");

  // Cancellation reaches grandchildren: the build's child starts a grandchild
  // that would otherwise outlive the build (no process groups on Windows).
  // detached: Node puts non-detached children in a kill-on-close job object, so
  // they die with their parent anyway; real build tools (MSBuild, cl.exe, make)
  // do not, and a detached grandchild models them.
  const repo = path.join(tmp, "tree");
  fs.mkdirSync(path.join(repo, ".pi"), { recursive: true });
  const pidFile = path.join(repo, "grandchild.pid");
  const script = path.join(repo, "tree.js");
  fs.writeFileSync(script, `
const { spawn } = require("node:child_process");
const g = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore", detached: true, windowsHide: true });
g.unref();
require("node:fs").writeFileSync(${JSON.stringify(pidFile)}, String(g.pid));
setInterval(() => {}, 1000);
`);
  fs.writeFileSync(path.join(repo, ".pi", "project.json"), JSON.stringify({ build: { command: process.execPath, args: [script] } }));
  const controller = new AbortController();
  const pending = runBuild(repo, { signal: controller.signal, killGraceMs: 200 });
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(pidFile) && Date.now() < deadline) await delay(50);
  const grandchild = Number(fs.readFileSync(pidFile, "utf8"));
  assert.ok(alive(grandchild), "grandchild started");
  controller.abort();
  const result = await pending;
  assert.equal(result.cancelled, true);
  const killDeadline = Date.now() + 5_000;
  while (alive(grandchild) && Date.now() < killDeadline) await delay(100);
  const survived = alive(grandchild);
  if (survived) { try { process.kill(grandchild); } catch {} }
  assert.equal(survived, false, "cancelling a build ends its grandchildren");

  // Worker slots: two per root, exclusive within this process and others.
  const root = path.join(tmp, "workers");
  const first = await acquireManagedWorker({ root });
  const second = await acquireManagedWorker({ root });
  await assert.rejects(acquireManagedWorker({ root }), { code: "MANAGED_WORKER_CAPACITY" });
  await first.release();
  const third = await acquireManagedWorker({ root });
  assert.equal(third.environment.PI_MANAGED_WORKER_SLOT, "0", "a released slot can be taken again");
  await second.release();
  await third.release();

  // A slot held by another process blocks this one and is freed when that
  // process is killed (no release call), as flock is on POSIX.
  const holder = spawn(process.execPath, ["-e", `
const { acquireManagedWorker } = require(${JSON.stringify(path.join(__dirname, "..", "src", "resource-guard.js"))});
acquireManagedWorker({ root: ${JSON.stringify(root)}, limit: 1 }).then(() => { process.stdout.write("held"); setInterval(() => {}, 1000); });
`], { stdio: ["ignore", "pipe", "inherit"] });
  await new Promise((resolve) => holder.stdout.once("data", resolve));
  await assert.rejects(acquireManagedWorker({ root, limit: 1 }), { code: "MANAGED_WORKER_CAPACITY" });
  holder.kill();
  await new Promise((resolve) => holder.once("exit", resolve));
  const afterCrash = await acquireManagedWorker({ root, limit: 1 });
  await afterCrash.release();

  console.log("build-runner windows tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
