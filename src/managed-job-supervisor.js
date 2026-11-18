"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const {
  ownProcessGroup,
  processGroupAlive,
  resourceGuardConfig,
  terminateOwnedProcessGroup,
  watchOwnedProcessGroupRss,
} = require("./resource-guard.js");
const { gitBashPath } = require("./win-exec.js");

function writePrivateJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temp, file);
  try { fs.chmodSync(file, 0o600); } catch {}
}

function readLaunch(file) {
  const launch = JSON.parse(fs.readFileSync(file, "utf8"));
  try { fs.rmSync(file, { force: true }); } catch {}
  if (!launch || launch.schemaVersion !== 1 || !launch.command || !launch.cwd || !launch.exitFile || !launch.logFile || !launch.guardFile) {
    throw new Error("invalid managed job launch record");
  }
  return launch;
}

function signalExitCode(signal) {
  return 128 + Number(os.constants.signals?.[signal] || 0);
}

/** The stop request file for a job (see bg-jobs stopJob). */
function stopRequestFile(launch) {
  return String(launch.guardFile).replace(/\.guard\.json$/, ".stop");
}

/**
 * The shell that runs the job command. POSIX: sh -c. Windows: Git Bash (the
 * shell Pi's bash tool uses, so commands mean the same thing), else cmd.exe.
 */
function commandShell(command) {
  if (process.platform !== "win32") return { command: "sh", args: ["-c", command], options: {} };
  const bash = gitBashPath(process.env);
  if (bash) return { command: bash, args: ["-c", command], options: {} };
  return { command: process.env.ComSpec || "cmd.exe", args: ["/d", "/s", "/c", `"${command}"`], options: { windowsVerbatimArguments: true } };
}

async function supervise(launchFile) {
  const launch = readLaunch(launchFile);
  const config = resourceGuardConfig(launch.resourceGuard || {});
  // Windows: an append-mode handle lacks FILE_WRITE_DATA, and Git Bash (MSYS)
  // exits 1 without output when its stdout is such a handle. Each job's log is
  // a new file, so open it for writing; the shared handle keeps writes ordered.
  const logFd = fs.openSync(launch.logFile, process.platform === "win32" ? "w" : "a", 0o600);
  let child;
  let ownership;
  let monitor;
  let terminationPromise;
  let stopReason;
  let childCode = null;
  let childSignal = null;
  let lastGuardWrite = 0;
  const state = {
    schemaVersion: 1,
    supervisorPid: process.pid,
    phase: "starting",
    rssLimitBytes: config.rssLimitBytes,
    rssPollMs: config.rssPollMs,
    termGraceMs: config.termGraceMs,
    currentRssBytes: 0,
    peakRssBytes: 0,
    processGroupMembers: 0,
    terminationReason: null,
    signals: [],
  };
  const writeState = (force = false) => {
    const now = Date.now();
    if (!force && now - lastGuardWrite < Math.max(250, config.rssPollMs)) return;
    lastGuardWrite = now;
    try { writePrivateJson(launch.guardFile, state); } catch {}
  };
  const logGuard = (message) => {
    try { fs.writeSync(logFd, `[pi resource guard] ${message}\n`); } catch {}
  };
  const finishExit = (code) => {
    try { fs.writeFileSync(launch.exitFile, `${Number.isInteger(code) ? code : 1}\n`, { mode: 0o600 }); } catch {}
  };
  const requestTermination = (reason, usage) => {
    if (!stopReason) stopReason = reason;
    if (usage) {
      state.currentRssBytes = usage.rssBytes;
      state.peakRssBytes = Math.max(state.peakRssBytes, usage.peakRssBytes || usage.rssBytes);
      state.processGroupMembers = usage.members;
    }
    state.terminationReason = stopReason;
    if (!ownership) return Promise.resolve({ signals: [], termSent: false, killSent: false });
    if (terminationPromise) return terminationPromise;
    state.phase = "terminating";
    writeState(true);
    logGuard(`${reason}; sending SIGTERM to owned process group ${ownership.processGroupId}`);
    monitor?.stop();
    terminationPromise = terminateOwnedProcessGroup(ownership, {
      graceMs: config.termGraceMs,
      pollMs: Math.min(100, config.rssPollMs),
    }).then((result) => {
      state.signals = result.signals;
      if (result.killSent) logGuard(`owned process group ignored SIGTERM for ${config.termGraceMs}ms; sent SIGKILL`);
      return result;
    });
    return terminationPromise;
  };

  const onSignal = () => { void requestTermination("explicit-stop"); };
  process.on("SIGTERM", onSignal);
  process.on("SIGINT", onSignal);
  // Windows has no SIGTERM delivery: process.kill() terminates the supervisor
  // outright and its command tree would be orphaned. stopJob writes a stop
  // request file instead, which the supervisor polls.
  const stopFile = stopRequestFile(launch);
  const stopPoll = process.platform === "win32"
    ? setInterval(() => { if (fs.existsSync(stopFile)) onSignal(); }, 250)
    : null;
  writeState(true);

  try {
    if (stopReason) throw Object.assign(new Error("managed job stopped before launch"), { name: "AbortError" });
    const shell = commandShell(launch.command);
    const spawnedAt = Date.now();
    child = spawn(shell.command, shell.args, {
      cwd: launch.cwd,
      detached: true,
      stdio: ["ignore", logFd, logFd],
      env: process.env,
      windowsHide: true,
      ...shell.options,
    });
    ownership = ownProcessGroup(child, { spawnedAt });
    state.commandPid = child.pid;
    state.processGroupId = child.pid;
    state.phase = "running";
    state.startedAt = new Date().toISOString();
    writeState(true);

    const childClosed = new Promise((resolve) => {
      child.on("error", (error) => {
        logGuard(`command launch failed: ${error?.message || String(error)}`);
        childCode = 127;
        resolve();
      });
      child.on("close", (code, signal) => {
        childCode = Number.isInteger(code) ? code : null;
        childSignal = signal || null;
        resolve();
      });
    });

    monitor = watchOwnedProcessGroupRss(ownership, {
      limitBytes: config.rssLimitBytes,
      pollMs: config.rssPollMs,
      onSample: (usage) => {
        state.currentRssBytes = usage.rssBytes;
        state.peakRssBytes = Math.max(state.peakRssBytes, usage.peakRssBytes || usage.rssBytes);
        state.processGroupMembers = usage.members;
        writeState();
      },
      onExceeded: (usage) => {
        logGuard(`RSS ${usage.rssBytes} bytes exceeded ${usage.limitBytes}-byte limit`);
        void requestTermination("rss-limit", usage);
      },
    });

    await childClosed;
    if (terminationPromise) await terminationPromise;
    else if (processGroupAlive(child.pid)) await requestTermination("descendant-cleanup");

    const sample = monitor?.stop() || {};
    state.peakRssBytes = Math.max(state.peakRssBytes, Number(sample.peakRssBytes || 0));
    state.currentRssBytes = 0;
    state.processGroupMembers = 0;
    state.phase = "finished";
    state.finishedAt = new Date().toISOString();
    writeState(true);

    if (stopReason === "rss-limit") finishExit(137);
    else if (stopReason === "explicit-stop") finishExit(signalExitCode("SIGTERM"));
    else if (Number.isInteger(childCode)) finishExit(childCode);
    else if (childSignal) finishExit(signalExitCode(childSignal));
    else finishExit(1);
  } catch (error) {
    const aborted = error?.name === "AbortError" && stopReason === "explicit-stop";
    state.phase = "finished";
    state.finishedAt = new Date().toISOString();
    state.error = aborted ? null : String(error?.message || error);
    state.terminationReason = stopReason || (aborted ? "explicit-stop" : "supervisor-error");
    writeState(true);
    if (!aborted) logGuard(`supervisor failed: ${state.error}`);
    finishExit(aborted ? signalExitCode("SIGTERM") : 1);
  } finally {
    monitor?.stop();
    if (stopPoll) clearInterval(stopPoll);
    try { fs.rmSync(stopFile, { force: true }); } catch {}
    try { fs.closeSync(logFd); } catch {}
  }
}

const launchFile = process.argv[2];
if (!launchFile) process.exitCode = 2;
else supervise(path.resolve(launchFile)).catch(() => { process.exitCode = 1; });
