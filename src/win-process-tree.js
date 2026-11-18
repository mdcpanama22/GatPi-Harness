"use strict";
// Windows replacement for the /proc process-group primitives in resource-guard.
//
// Windows has no process groups and no /proc. A job is the process tree under
// the shell the supervisor launched: every process whose ParentProcessId chain
// reaches the root. Windows keeps a child's ParentProcessId after the parent
// exits, so descendants stay attributable when the shell is gone. A process
// counts only if it was created no earlier than the root, which guards against
// PID reuse. One snapshot (Win32_Process via PowerShell, ~0.5 s) gives parent,
// working set (the RSS equivalent) and creation time for every process.
const { spawnSync } = require("node:child_process");

const SNAPSHOT_SCRIPT = [
  "Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,WorkingSetSize,CreationDate",
  "| ForEach-Object { '{0},{1},{2},{3}' -f $_.ProcessId,$_.ParentProcessId,$_.WorkingSetSize,",
  "$(if ($_.CreationDate) { $_.CreationDate.ToFileTimeUtc() } else { 0 }) }",
].join(" ");

/** All processes: [{ pid, parentPid, rssBytes, created }] (created = FILETIME string). */
function snapshot() {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", SNAPSHOT_SCRIPT], {
    encoding: "utf8",
    windowsHide: true,
    timeout: 15000,
    maxBuffer: 8 * 1024 * 1024,
  });
  if (result.status !== 0 || !result.stdout) return [];
  const processes = [];
  for (const line of result.stdout.split(/\r?\n/)) {
    const [pid, parentPid, rss, created] = line.trim().split(",");
    if (!pid) continue;
    processes.push({ pid: Number(pid), parentPid: Number(parentPid), rssBytes: Number(rss) || 0, created: String(created || "0") });
  }
  return processes;
}

function olderThan(a, b) {
  // FILETIME strings are 18-digit integers; compare as BigInt to avoid float loss.
  try { return BigInt(a) < BigInt(b); } catch { return false; }
}

/** Identity of one process ({ pid, startTime }) or null when it is not running. */
function identity(pid, processes = snapshot()) {
  const entry = processes.find((item) => item.pid === Number(pid));
  return entry ? { pid: entry.pid, startTime: entry.created, state: "R", processGroupId: entry.pid } : null;
}

/** FILETIME (100 ns since 1601) for a JavaScript timestamp. */
function fileTime(ms) {
  return String((BigInt(Math.floor(ms)) + 11644473600000n) * 10000n);
}

/**
 * The root and its live descendants.
 * - startTime: the root's exact creation time when it was seen running; the root
 *   PID counts only while it still has that creation time (PID reuse guard).
 * - notBefore: the job's spawn time; no member may be older (a PID reused by an
 *   unrelated, older process is never included or killed).
 */
function treeMembers(rootPid, { startTime = null, notBefore = null } = {}, processes = snapshot()) {
  const root = Number(rootPid);
  const lowerBound = startTime || notBefore;
  const byParent = new Map();
  for (const item of processes) {
    if (!byParent.has(item.parentPid)) byParent.set(item.parentPid, []);
    byParent.get(item.parentPid).push(item);
  }
  const members = [];
  const rootEntry = processes.find((item) => item.pid === root);
  const rootIsOurs = rootEntry && (startTime ? rootEntry.created === String(startTime) : notBefore ? !olderThan(rootEntry.created, notBefore) : false);
  if (rootIsOurs) members.push(rootEntry);
  // A root PID now held by a different process means our tree's parent link is gone.
  if (rootEntry && !rootIsOurs && startTime) return members;
  const queue = [root];
  const seen = new Set([root]);
  while (queue.length) {
    const parent = queue.shift();
    for (const child of byParent.get(parent) || []) {
      if (seen.has(child.pid)) continue;
      if (!lowerBound || olderThan(child.created, lowerBound)) continue;
      seen.add(child.pid);
      members.push(child);
      queue.push(child.pid);
    }
  }
  return members;
}

/**
 * Ends exactly the given processes (already filtered by treeMembers): a polite
 * taskkill first (force=false; console programs usually ignore it), then /F.
 * No /T: descendants are listed explicitly, so a reused PID's tree is never hit.
 */
function killProcesses(pids, { force }) {
  const unique = [...new Set(pids.map(Number).filter((pid) => Number.isInteger(pid) && pid > 0 && pid !== process.pid))];
  if (!unique.length) return false;
  const args = [];
  for (const pid of unique) args.push("/PID", String(pid));
  if (force) args.push("/F");
  const result = spawnSync("taskkill.exe", args, { windowsHide: true, encoding: "utf8", timeout: 15000 });
  return result.status === 0 || result.status === 128;
}

module.exports = { snapshot, identity, treeMembers, killProcesses, fileTime };
