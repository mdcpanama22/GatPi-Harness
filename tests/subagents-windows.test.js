"use strict";
// Windows-only subagent behaviour: children launch on Pi's own runtime, process
// trees are cleaned up promptly, and patches transfer byte-exact even when Git
// would convert line endings (core.autocrlf=true, Git for Windows' default).
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");
const { SubagentRunner } = require("../src/subagents");
const { ownProcessGroup, terminateOwnedProcessGroup } = require("../src/resource-guard");
const { SubagentWorkspaceManager } = require("../src/subagent-workspaces");
const { SubagentPatchService } = require("../src/subagent-patches");
const { tmpFixture } = require("./helpers/tmp-fixture");

if (process.platform !== "win32") {
  console.log("subagents windows tests skipped (not Windows)");
  process.exit(0);
}

const alive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };
function git(cwd, args) { return execFileSync("git", args, { cwd, encoding: "utf8", env: { ...process.env, GIT_AUTHOR_NAME: "Pi Test", GIT_AUTHOR_EMAIL: "pi@example.invalid", GIT_COMMITTER_NAME: "Pi Test", GIT_COMMITTER_EMAIL: "pi@example.invalid" } }).trim(); }

(async () => {
  const tmp = tmpFixture("pi-subagents-win-");

  // 1. Without an explicit command, a child runs on this runtime and CLI script
  // (a bundled Pi has no `pi` on PATH). An explicit command is used as given.
  const previous = process.env.PI_SUBAGENT_RPC_COMMAND;
  delete process.env.PI_SUBAGENT_RPC_COMMAND;
  try {
    const runner = new SubagentRunner();
    const own = runner.rpcArgs({ id: "own-runtime", task: "x" }, { cwd: tmp });
    assert.equal(own.command, process.execPath);
    assert.equal(own.args[0], process.argv[1], "the CLI script comes first");
    assert.ok(own.args.includes("--mode") && own.args.includes("rpc"));
    const explicit = runner.rpcArgs({ id: "explicit", task: "x" }, { cwd: tmp, rpc: { command: "pi" } });
    assert.equal(explicit.command, "pi");
    assert.equal(explicit.args[0], "--mode", "an explicit command gets no script prefix");
  } finally {
    if (previous === undefined) delete process.env.PI_SUBAGENT_RPC_COMMAND;
    else process.env.PI_SUBAGENT_RPC_COMMAND = previous;
  }

  // 2. Cleanup of an already-exited child returns at once (no grace, no sweeps),
  // and a hidden console child, which never sees a polite taskkill, is forced
  // without waiting out the full POSIX grace period.
  const quick = spawn(process.execPath, ["-e", ""], { detached: true, stdio: "ignore", windowsHide: true });
  const quickOwned = ownProcessGroup(quick, { snapshot: false });
  await new Promise((resolve) => quick.once("exit", resolve));
  let started = Date.now();
  const quickResult = await terminateOwnedProcessGroup(quickOwned, { graceMs: 5000 });
  assert.deepEqual(quickResult.signals, []);
  assert.ok(Date.now() - started < 1500, `exited child cleanup took ${Date.now() - started} ms`);

  const stubborn = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { detached: true, stdio: "ignore", windowsHide: true });
  const stubbornOwned = ownProcessGroup(stubborn, { snapshot: false });
  started = Date.now();
  const stubbornResult = await terminateOwnedProcessGroup(stubbornOwned, { graceMs: 5000 });
  const elapsed = Date.now() - started;
  const survived = alive(stubborn.pid);
  if (survived) { try { process.kill(stubborn.pid); } catch {} }
  assert.equal(survived, false);
  assert.deepEqual(stubbornResult.signals, ["SIGTERM", "SIGKILL"]);
  assert.ok(elapsed < 4500, `console child cleanup waited ${elapsed} ms (the 5 s grace is capped on Windows)`);

  // 3. A patch transfers byte-exact under core.autocrlf=true: a CRLF edit and an
  // LF new file (as Pi's write tool produces) both arrive unchanged.
  const repo = path.join(tmp, "repo");
  fs.mkdirSync(repo);
  git(repo, ["init", "-q"]);
  git(repo, ["config", "core.autocrlf", "true"]);
  fs.writeFileSync(path.join(repo, "app.txt"), "base\r\n");
  git(repo, ["add", "."]);
  git(repo, ["commit", "-qm", "base"]);
  const manager = new SubagentWorkspaceManager({ cwd: repo });
  const lease = manager.acquire({ subagentId: "crlf", parentSessionId: "sess", task: "propose patch" });
  fs.writeFileSync(path.join(lease.cwd, "app.txt"), "child\r\nchange\r\n");
  fs.writeFileSync(path.join(lease.cwd, "new.txt"), "new file\n");
  const capture = manager.capture(lease, { status: "succeeded" });
  const patches = new SubagentPatchService({ cwd: repo });
  const applied = await patches.apply(patches.preview(capture), { explicit: true, verify: async () => ({ status: "passed", evidence: [] }) });
  assert.equal(applied.applied, true);
  assert.equal(fs.readFileSync(path.join(repo, "app.txt"), "utf8"), "child\r\nchange\r\n");
  assert.equal(fs.readFileSync(path.join(repo, "new.txt"), "utf8"), "new file\n", "an LF file stays LF");

  console.log("subagents windows tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
