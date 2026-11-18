"use strict";

// Private client configuration shared by the CLI and the Pi extension. Values are
// read from an owner-only env file; they are never logged or returned to callers.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { parseEnv } = require("node:util");
const { execFileSync } = require("node:child_process");

const required = ["REDIS_HOST", "REDIS_USERNAME", "REDIS_PASSWORD", "REDIS_CA", "REDIS_CERT", "REDIS_KEY"];

function configFile(env = process.env) {
  const file = env.PI_QUEUE_ENV || path.join(env.HOME || os.homedir(), ".config", "pi-queue", "client.env");
  if (!path.isAbsolute(file)) throw new Error("PI_QUEUE_ENV must be an absolute private connection-file path");
  return file;
}

// Windows has no POSIX mode bits (stat.mode is always 0o666), so "owner-only" means
// the file's ACL names only the current user plus SYSTEM and Administrators, which
// can read any file anyway. The icacls output is parsed by aclPrincipals below.
const WINDOWS_TRUSTED = ["nt authority\\system", "builtin\\administrators"];

function aclPrincipals(icaclsOutput, file) {
  const lines = icaclsOutput.split(/\r?\n/);
  if (!lines[0] || !lines[0].toLowerCase().startsWith(file.toLowerCase())) return null;
  lines[0] = lines[0].slice(file.length);
  const principals = [];
  for (const line of lines) {
    const match = /^\s*(.+?):(\([^)]*\))+\s*$/.exec(line);
    if (match) principals.push(match[1].trim());
  }
  return principals;
}

function windowsAclIsPrivate(principals, env = process.env) {
  if (!principals || principals.length === 0) return false;
  // `env` locates the config file; the identity is the running process's user.
  const user = (env.USERNAME || process.env.USERNAME || os.userInfo().username).toLowerCase();
  const domain = env.USERDOMAIN || process.env.USERDOMAIN;
  const domainUser = domain ? `${domain}\\${user}`.toLowerCase() : null;
  return principals.every((name) => {
    const lower = name.toLowerCase();
    return lower === user || lower === domainUser || WINDOWS_TRUSTED.includes(lower);
  });
}

function windowsFileIsPrivate(file, env) {
  const resolved = path.resolve(file);
  let output;
  try {
    output = execFileSync("icacls", [resolved], { encoding: "utf8", windowsHide: true, timeout: 5000 });
  } catch {
    return false;
  }
  return windowsAclIsPrivate(aclPrincipals(output, resolved), env);
}

function fileIsPrivate(file, stat, env) {
  if (process.platform === "win32") return windowsFileIsPrivate(file, env);
  return !(stat.mode & 0o077) && !(process.getuid && stat.uid !== process.getuid());
}

function clientConfiguration(env = process.env) {
  const file = configFile(env);
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size > 64 * 1024 || !fileIsPrivate(file, stat, env)) {
    throw new Error("Queue client configuration must be an owner-only regular file of at most 64 KiB");
  }
  const values = parseEnv(fs.readFileSync(file, "utf8"));
  if (required.some((key) => !values[key])) throw new Error("Queue client configuration is missing required Redis/TLS fields");
  if (["REDIS_CA", "REDIS_CERT", "REDIS_KEY"].some((key) => !path.isAbsolute(values[key]))) {
    throw new Error("Queue certificate paths must be absolute");
  }
  return { file, values };
}

// ioredis options for the TLS, client-certificate, ACL-user broker.
function connectionOptions(values) {
  return {
    host: values.REDIS_HOST,
    port: Number(values.REDIS_PORT || 6380),
    username: values.REDIS_USERNAME,
    password: values.REDIS_PASSWORD,
    tls: {
      ca: fs.readFileSync(values.REDIS_CA),
      cert: fs.readFileSync(values.REDIS_CERT),
      key: fs.readFileSync(values.REDIS_KEY),
    },
  };
}

module.exports = { clientConfiguration, connectionOptions, aclPrincipals, windowsAclIsPrivate };
