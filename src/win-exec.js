"use strict";
// Cross-platform executable lookup and launch.
//
// POSIX behaviour is unchanged: PATH lookup with X_OK, direct execFile.
// On Windows:
// - lookups try each PATHEXT extension (rg -> rg.exe, npm -> npm.cmd);
// - .cmd/.bat files cannot be started by execFile/spawn without a shell, so
//   they run through `cmd.exe /d /s /c` with every argument quoted and cmd
//   metacharacters caret-escaped (the scheme cross-spawn uses, MIT), so
//   arguments arrive intact and cannot chain extra commands;
// - `bash` and `sh` fall back to Git Bash in the locations Pi itself checks.
const fs = require("node:fs");
const path = require("node:path");

// Windows environment names are case-insensitive, but a copied env object is a
// plain object (and MSYS shells uppercase names: PROGRAMFILES, not ProgramFiles).
function envValue(env, name) {
  if (env[name] !== undefined) return env[name];
  const lower = name.toLowerCase();
  const key = Object.keys(env).find((candidate) => candidate.toLowerCase() === lower);
  return key === undefined ? undefined : env[key];
}

function windowsExtensions(env) {
  return String(envValue(env, "PATHEXT") || ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean);
}

function isFile(file) {
  try { return fs.statSync(file).isFile(); } catch { return false; }
}

/** Like `which`: { bin, found, path }. Honors PATHEXT on Windows. */
function findExecutable(bin, env = process.env, platform = process.platform) {
  const hasSep = bin.includes("/") || bin.includes("\\") || path.isAbsolute(bin);
  const pathValue = platform === "win32" ? envValue(env, "PATH") : env.PATH;
  const dirs = hasSep ? [""] : String(pathValue || "").split(path.delimiter).filter(Boolean);
  const base = hasSep ? path.resolve(bin) : bin;
  if (platform === "win32") {
    const hasExt = path.extname(base) !== "";
    // An explicit path names the file exactly (first), then PATHEXT variants;
    // a bare name searched on PATH only matches PATHEXT files, as Windows does.
    const extensions = hasExt ? [""] : hasSep ? ["", ...windowsExtensions(env)] : windowsExtensions(env);
    for (const dir of dirs) {
      for (const ext of extensions) {
        const candidate = dir ? path.join(dir, base + ext) : base + ext;
        if (isFile(candidate)) return { bin, found: true, path: candidate };
      }
    }
    return { bin, found: false, path: hasSep ? base : null };
  }
  for (const dir of dirs) {
    const candidate = dir ? path.join(dir, base) : base;
    try { fs.accessSync(candidate, fs.constants.X_OK); return { bin, found: true, path: candidate }; } catch {}
  }
  return { bin, found: false, path: hasSep ? base : null };
}

/** Git Bash, in the order Pi resolves it: Program Files, Program Files (x86), then PATH. */
function gitBashPath(env = process.env) {
  const candidates = ["ProgramFiles", "ProgramFiles(x86)"]
    .map((name) => envValue(env, name))
    .filter(Boolean)
    .map((root) => path.join(root, "Git", "bin", "bash.exe"));
  for (const candidate of candidates) if (isFile(candidate)) return candidate;
  const onPath = findExecutable("bash", env, "win32");
  return onPath.found ? onPath.path : null;
}

const CMD_META = /([()\][%!^"`<>&|;, *?])/g;
function escapeCmdCommand(command) {
  return command.replace(CMD_META, "^$1");
}
function escapeCmdArgument(arg, doubleEscape) {
  let out = String(arg);
  // Backslashes before a quote are doubled and the quote escaped (MSVCRT rules);
  // trailing backslashes are doubled so they don't escape the closing quote.
  out = out.replace(/(\\*)"/g, '$1$1\\"');
  out = out.replace(/(\\*)$/, "$1$1");
  out = `"${out}"`;
  out = out.replace(CMD_META, "^$1");
  // Batch files re-parse their arguments once more when expanding %*.
  if (doubleEscape) out = out.replace(CMD_META, "^$1");
  return out;
}

/**
 * Returns { command, args, options } ready for execFile/spawn. Merge `options`
 * into the caller's options. On POSIX this is the input unchanged.
 */
function resolveSpawn(command, args = [], env = process.env, platform = process.platform) {
  if (platform !== "win32") return { command, args, options: {} };
  let resolved = findExecutable(command, env, platform);
  // sh and bash fall back to Git Bash, which also runs POSIX sh scripts.
  if (!resolved.found && ["bash", "sh"].includes(path.basename(command).toLowerCase().replace(/\.exe$/, ""))) {
    const bash = gitBashPath(env);
    if (bash) resolved = { bin: command, found: true, path: bash };
  }
  if (!resolved.found) return { command, args, options: {} };
  if (!/\.(cmd|bat)$/i.test(resolved.path)) return { command: resolved.path, args, options: {} };

  // Batch files forward arguments with %* (npm.cmd, node_modules\.bin shims and
  // most others), and cmd re-parses that expansion, so every .cmd/.bat argument
  // is escaped twice. Escaping once lets a quote in an argument break out and
  // chain a second command (the "BatBadBut" class, CVE-2024-27980).
  const line = [escapeCmdCommand(path.normalize(resolved.path)), ...args.map((arg) => escapeCmdArgument(arg, true))].join(" ");
  return {
    command: envValue(env, "ComSpec") || process.env.ComSpec || "cmd.exe",
    args: ["/d", "/s", "/c", `"${line}"`],
    options: { windowsVerbatimArguments: true },
  };
}

module.exports = { findExecutable, gitBashPath, resolveSpawn };
