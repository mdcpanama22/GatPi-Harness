"use strict";
// Code tools on every platform: ripgrep resolves from PATH or Pi's managed
// bin directory, and rg/codegraph launch through resolveSpawn so .cmd shims
// work on Windows.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { resolveRgBin, runRg } = require("../src/lexical-search-adapter.js");
const { runCodegraphSync } = require("../src/codegraph-adapter.js");

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "code-tools-"));
const win = process.platform === "win32";
try {
  // ripgrep resolution: explicit override > PATH > Pi's managed bin > "rg".
  const agentDir = path.join(tmp, "agent");
  fs.mkdirSync(path.join(agentDir, "bin"), { recursive: true });
  const emptyPath = path.join(tmp, "empty-path");
  fs.mkdirSync(emptyPath);
  const base = { PATH: emptyPath, PATHEXT: process.env.PATHEXT, PI_CODING_AGENT_DIR: agentDir };
  assert.equal(resolveRgBin({ ...base, PI_CODE_CONTEXT_RG_BIN: "C:/custom/rg" }), "C:/custom/rg");
  assert.equal(resolveRgBin(base), "rg", "nothing installed: plain rg, so the error says what is missing");
  const managed = path.join(agentDir, "bin", win ? "rg.exe" : "rg");
  fs.writeFileSync(managed, "", { mode: 0o755 });
  assert.equal(resolveRgBin(base), managed, "Pi's managed ripgrep is used when rg is not on PATH");

  // .cmd shims launch (Windows) / scripts launch (POSIX), with spaces in arguments.
  const fake = (name, body) => {
    const file = path.join(tmp, win ? `${name}.cmd` : name);
    // "--" stops node from reading forwarded flags such as --json as its own.
    fs.writeFileSync(file, win ? `@"${process.execPath}" -e "${body}" -- %*\r\n` : `#!/bin/sh\nexec "${process.execPath}" -e '${body}' -- "$@"\n`, { mode: 0o755 });
    return file;
  };
  const rg = fake("rg", "console.log(JSON.stringify(process.argv.slice(1)))");
  (async () => {
    const result = await runRg(tmp, ["--json", "needle with space"], { bin: rg });
    assert.equal(result.ok, true);
    assert.deepEqual(JSON.parse(result.stdout.trim()), ["--json", "needle with space"]);

    const codegraph = fake("codegraph", "console.log('cg:' + process.argv.slice(1).join('|'))");
    const cg = runCodegraphSync(tmp, ["status", "a b"], { bin: codegraph });
    assert.equal(cg.ok, true, JSON.stringify(cg));
    assert.equal(cg.stdout.trim(), "cg:status|a b");

    fs.rmSync(tmp, { recursive: true, force: true });
    console.log("code-tools-windows tests passed");
  })().catch((error) => { console.error(error); process.exit(1); });
} catch (error) {
  fs.rmSync(tmp, { recursive: true, force: true });
  throw error;
}
