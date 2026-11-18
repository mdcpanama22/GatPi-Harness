"use strict";
// Cross-platform executable lookup and launch. On Windows, `npm`, `npx`, `pnpm`
// and `yarn` are .cmd shims that execFile cannot start directly, and PATH
// lookups need PATHEXT (rg is rg.exe). Arguments must survive cmd.exe quoting.
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { findExecutable, resolveSpawn, gitBashPath } = require("../src/win-exec.js");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "win-exec-"));
try {
  if (process.platform === "win32") {
    // PATHEXT lookup: a bare name finds tool.cmd / tool.exe.
    fs.writeFileSync(path.join(tmp, "echo-args.cmd"), `@"${process.execPath}" -e "console.log(JSON.stringify(process.argv.slice(1)))" %*\r\n`);
    const env = { ...process.env, PATH: `${tmp}${path.delimiter}${process.env.PATH}` };
    const found = findExecutable("echo-args", env);
    assert.equal(found.found, true);
    assert.equal(path.basename(found.path).toLowerCase(), "echo-args.cmd");
    assert.equal(findExecutable("definitely-not-installed-xyz", env).found, false);
    // An explicit path names the file exactly, even without an extension.
    const explicit = path.join(tmp, "tool-no-ext");
    fs.writeFileSync(explicit, "");
    assert.deepEqual(findExecutable(explicit, env), { bin: explicit, found: true, path: explicit });
    assert.equal(findExecutable(path.join(tmp, "echo-args"), env).found, true, "explicit path still tries PATHEXT");
    // A bare name on PATH ignores extensionless files, as Windows does.
    assert.equal(findExecutable("tool-no-ext", env).found, false);
    assert.equal(findExecutable("node", env).found, true);

    // .cmd files run through cmd.exe and arguments arrive unchanged.
    const args = ["plain", "with space", "a&b", "(paren)", "pipe|x", "semi;colon", "tail\\"];
    const spawn = resolveSpawn("echo-args", args, env);
    assert.equal(path.basename(spawn.command).toLowerCase(), "cmd.exe");
    assert.equal(spawn.options.windowsVerbatimArguments, true);
    const out = execFileSync(spawn.command, spawn.args, { env, encoding: "utf8", ...spawn.options });
    assert.deepEqual(JSON.parse(out.trim()), args);

    // Injection attempts stay literal arguments and never run a second command.
    const marker = path.join(tmp, "pwned.txt");
    const hostileArgs = [
      `x" & echo pwned > "${marker}`,
      `& echo pwned > "${marker}"`,
      `" | echo pwned > "${marker}`,
      `\\" && echo pwned > "${marker}" && "`,
      "%PATH%",
      "100%",
      "!VAR!",
      "^caret^",
    ];
    const hostile = resolveSpawn("echo-args", hostileArgs, env);
    const hostileOut = execFileSync(hostile.command, hostile.args, { env, encoding: "utf8", ...hostile.options });
    assert.equal(fs.existsSync(marker), false, "cmd metacharacters must not run a second command");
    assert.deepEqual(JSON.parse(hostileOut.trim()), hostileArgs, "hostile arguments arrive unchanged");

    // .exe files run directly.
    const node = resolveSpawn("node", ["-e", "process.stdout.write('ok')"], env);
    assert.notEqual(path.basename(node.command).toLowerCase(), "cmd.exe");
    assert.equal(execFileSync(node.command, node.args, { encoding: "utf8", ...node.options }), "ok");

    // npm, the case test-runner needs, resolves and runs.
    const npm = resolveSpawn("npm", ["--version"], process.env);
    assert.match(execFileSync(npm.command, npm.args, { encoding: "utf8", ...npm.options }).trim(), /^\d+\.\d+\.\d+/);

    // bash resolves to Git Bash even when it is not on PATH.
    const gitBash = gitBashPath(process.env);
    if (gitBash) {
      const bash = resolveSpawn("bash", ["-c", "echo hi"], { ...process.env, PATH: path.dirname(process.execPath) });
      assert.equal(bash.command, gitBash);
      assert.equal(execFileSync(bash.command, bash.args, { encoding: "utf8", ...bash.options }).trim(), "hi");
    }
  } else {
    // POSIX: unchanged behaviour (PATH lookup, direct execution).
    const tool = path.join(tmp, "tool");
    fs.writeFileSync(tool, "#!/bin/sh\necho \"$@\"\n", { mode: 0o755 });
    const env = { ...process.env, PATH: `${tmp}${path.delimiter}${process.env.PATH}` };
    assert.equal(findExecutable("tool", env).path, tool);
    const spawn = resolveSpawn("tool", ["a b"], env);
    assert.equal(spawn.command, "tool");
    assert.deepEqual(spawn.args, ["a b"]);
    assert.deepEqual(spawn.options, {});
  }
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
console.log("win-exec tests passed");
