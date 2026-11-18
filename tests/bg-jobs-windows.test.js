"use strict";
// Background jobs on native Windows: jobs start, report their exit code and
// output, and stopping a job ends its whole process tree (no orphans), even
// when the shell that started the command has already exited.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

if (process.platform !== "win32") {
  console.log("bg-jobs-windows tests skipped (POSIX uses process groups)");
  process.exit(0);
}

const { startJob, jobStatus, jobLogs, stopJob } = require("../src/bg-jobs.js");
const { processIdentity } = require("../src/resource-guard.js");
const { treeMembers, fileTime } = require("../src/win-process-tree.js");

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "bg-jobs win "));
const node = process.execPath.replace(/\\/g, "/");
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(check, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) { const value = check(); if (value) return value; await wait(200); }
  throw new Error(`timed out waiting for ${label}`);
}
function pidAlive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }

(async () => {
  try {
    // 1. A normal job runs through Git Bash (or cmd), logs output and records its exit code.
    const done = startJob(cwd, `echo hello-from-job && exit 3`, { resourceGuard: { rssPollMs: 500 } });
    assert.ok(done.ownership?.startTime, "the supervisor has a recorded identity, so it can be stopped later");
    const finished = await until(() => { const s = jobStatus(cwd, done.jobId); return s.status === "exited" ? s : null; }, 30000, "job exit");
    assert.equal(finished.exitCode, 3);
    assert.match(jobLogs(cwd, done.jobId).text, /hello-from-job/);

    // 2. A long job with a grandchild: stopping it ends the whole tree.
    const pidFile = path.join(cwd, "grandchild.pid").replace(/\\/g, "/");
    const grandchild = `require('child_process').spawn(process.execPath, ['-e', 'require(\\'fs\\').writeFileSync(\\'${pidFile}\\', String(process.pid)); setInterval(() => {}, 1000)'], { stdio: 'ignore' }); setInterval(() => {}, 1000)`;
    const longStartedAt = Date.now();
    const long = startJob(cwd, `"${node}" -e "${grandchild}"`, { resourceGuard: { rssPollMs: 500, termGraceMs: 1000 } });
    const grandchildPid = Number(await until(() => fs.existsSync(pidFile) && fs.readFileSync(pidFile, "utf8"), 30000, "grandchild start"));
    assert.ok(pidAlive(grandchildPid), "grandchild is running");
    const guard = await until(() => { const s = jobStatus(cwd, long.jobId); return s.resourceGuard?.processGroupMembers >= 2 ? s.resourceGuard : null; }, 30000, "process tree members");
    assert.ok(guard.currentRssBytes > 0, "memory of the job's processes is measured");
    const members = treeMembers(guard.processGroupId, { notBefore: fileTime(longStartedAt - 2000) }).map((item) => item.pid);
    assert.ok(members.includes(grandchildPid), "the grandchild belongs to the job's process tree");

    const stop = stopJob(cwd, long.jobId);
    assert.equal(stop.stopped, true);
    const stopped = await until(() => { const s = jobStatus(cwd, long.jobId); return s.status === "killed" && s.exitCode != null ? s : null; }, 30000, "job stop");
    assert.equal(stopped.status, "killed");
    await until(() => !pidAlive(grandchildPid), 10000, "grandchild exit");
    assert.equal(pidAlive(grandchildPid), false, "no orphaned grandchild after stop");
    assert.equal(processIdentity(long.supervisorPid), null, "supervisor has exited");

    console.log("bg-jobs-windows tests passed");
  } finally {
    // A supervisor may still be closing its log; retry, and never mask a test failure.
    try { fs.rmSync(cwd, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 }); } catch (error) { console.error(`cleanup: ${error.message}`); }
  }
})().catch((error) => { console.error(error); process.exit(1); });
