"use strict";
// Windows parity for the runtime policy.
//
// The POSIX policy denies recursive rm, sudo, curl|sh, mkfs/dd, recursive
// chmod/chown and writes under system or ~/.ssh prefixes. On native Windows
// the same intents are spelled differently: drive paths (C:\...), Git Bash
// drive paths (/c/...), PowerShell cmdlets and cmd builtins, and HOME is
// usually unset. These helpers let the existing policy apply the same rules.
const os = require("node:os");
const path = require("node:path");

/** The user's home directory, without depending on HOME (unset in most Windows processes). */
function homeDir() {
  return process.env.HOME || os.homedir();
}

/** Git Bash spells C:\x as /c/x. Convert on win32 so path checks see the real location. */
function fromGitBashPath(value, platform = process.platform) {
  if (platform !== "win32" || typeof value !== "string") return value;
  const match = /^\/([a-zA-Z])(?:\/(.*))?$/.exec(value);
  if (!match) return value;
  return `${match[1].toUpperCase()}:\\${(match[2] || "").replace(/\//g, "\\")}`;
}

/** Windows system folders, the counterpart of /etc, /usr, /bin, /sbin, /var. */
function windowsDenyPathPrefixes(env = process.env) {
  return [
    env.SystemRoot || env.SYSTEMROOT || "C:\\Windows",
    env.ProgramFiles || env.PROGRAMFILES || "C:\\Program Files",
    env["ProgramFiles(x86)"] || env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)",
    env.ProgramData || env.PROGRAMDATA || "C:\\ProgramData",
  ];
}

const RECURSIVE_DELETE_BIN = /^\s*(?:&\s*)?(?:Remove-Item|rm|ri|del|erase|rd|rmdir)(?:\.exe)?\b/i;
const RECURSIVE_FLAG = /\s(?:-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?|\/s)(?=\s|$)/i;
const DOWNLOAD = /\b(?:iwr|irm|curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile|Start-BitsTransfer)\b/i;
const EXECUTE = /\b(?:iex|Invoke-Expression)\b|\|\s*(?:powershell|pwsh|cmd)(?:\.exe)?\b/i;
const ELEVATE = [/\bStart-Process\b[^;|\n]*-Verb\s+['"]?RunAs\b/i, /^\s*runas(?:\.exe)?\s/i];
const DISK = [/\b(?:Format-Volume|Clear-Disk|Initialize-Disk|Remove-Partition)\b/i, /^\s*diskpart(?:\.exe)?\b/i, /^\s*format(?:\.com)?\s+[a-z]:/i];
const RECURSIVE_ACL = [/^\s*icacls(?:\.exe)?\b[^;|\n]*\s\/t(?=\s|$)/i, /^\s*takeown(?:\.exe)?\b[^;|\n]*\s\/r(?=\s|$)/i];
const WRITE_CMDLET = /^\s*(?:&\s*)?(?:Set-Content|Add-Content|Out-File|New-Item|Copy-Item|Move-Item|Rename-Item|Remove-Item|Tee-Object|sc|ac|ni|cpi|copy|cp|mi|move|mv|ren|tee|del|erase|rm|ri|rd|rmdir)(?:\.exe)?\b/i;
const ABSOLUTE_PATH = /(?:[A-Za-z]:\\[^\s'"`;|>]*|\/[a-zA-Z]\/[^\s'"`;|>]*)/g;
const INSTALL = [/\b(?:winget|choco|scoop)\s+install\b/i, /\bInstall-(?:Module|Package|Script)\b/i, /\b(?:npm|pnpm|yarn)\s+(?:install|add)\b/i, /\bpip\s+install\b/i];

function within(target, prefix) {
  const relative = path.win32.relative(prefix, target);
  return relative !== ".." && !relative.startsWith("..\\") && !path.win32.isAbsolute(relative);
}

/** Splits a PowerShell or cmd line into statements and pipeline stages. */
function segments(command) {
  return String(command || "").split(/\r?\n|;|&&|\|\||\|/).map((part) => part.trim()).filter(Boolean);
}

/**
 * Policy for a PowerShell (or cmd) command line: the same denials the POSIX
 * shell policy applies, in Windows spelling. Returns { denials, warnings } in
 * the shape evaluateShellCommand uses.
 */
function evaluatePowerShellCommand(command, { cwd = process.cwd(), denyPathPrefixes = [] } = {}) {
  const text = String(command || "");
  const denials = [];
  const warnings = [];
  const seen = new Set();
  const deny = (code, reason) => { const key = `${code}:${reason}`; if (!seen.has(key)) { seen.add(key); denials.push({ code, reason }); } };
  const warn = (reason) => { if (!seen.has(reason)) { seen.add(reason); warnings.push({ reason }); } };

  if (DOWNLOAD.test(text) && EXECUTE.test(text)) deny("denied-shell", "denied download-and-execute (PowerShell)");
  for (const part of segments(text)) {
    if (RECURSIVE_DELETE_BIN.test(part) && RECURSIVE_FLAG.test(part)) deny("denied-shell", "denied recursive delete (PowerShell/cmd)");
    if (ELEVATE.some((pattern) => pattern.test(part))) deny("denied-shell", "denied elevation (PowerShell/cmd)");
    if (DISK.some((pattern) => pattern.test(part))) deny("denied-shell", "denied disk formatting/partitioning");
    if (RECURSIVE_ACL.some((pattern) => pattern.test(part))) deny("denied-shell", "denied recursive ACL/ownership change");
    if (INSTALL.some((pattern) => pattern.test(part))) warn(`approval recommended for package/install command: ${part.split(/\s+/).slice(0, 2).join(" ")}`);

    const writes = WRITE_CMDLET.test(part) || />/.test(part);
    if (!writes) continue;
    for (const token of part.match(ABSOLUTE_PATH) || []) {
      const target = path.win32.resolve(cwd, fromGitBashPath(token, "win32"));
      for (const prefix of denyPathPrefixes) {
        if (within(target, path.win32.resolve(fromGitBashPath(prefix, "win32")))) deny("denied-path", `denied write target prefix: ${prefix}`);
      }
    }
  }
  return { denials, warnings };
}

/** The shell binaries whose -Command / /c argument is evaluated as PowerShell/cmd. */
function nestedWindowsCommand(argv) {
  const bin = path.win32.basename(String(argv[0] || "")).toLowerCase().replace(/\.exe$/, "");
  if (bin === "powershell" || bin === "pwsh") {
    const index = argv.findIndex((arg, i) => i > 0 && /^-(?:c|command)$/i.test(arg));
    return index > 0 ? argv.slice(index + 1).join(" ") : null;
  }
  if (bin === "cmd") {
    const index = argv.findIndex((arg, i) => i > 0 && /^\/[ck]$/i.test(arg));
    return index > 0 ? argv.slice(index + 1).join(" ") : null;
  }
  return null;
}

module.exports = { homeDir, fromGitBashPath, windowsDenyPathPrefixes, evaluatePowerShellCommand, nestedWindowsCommand };
