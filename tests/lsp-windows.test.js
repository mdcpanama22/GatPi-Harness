"use strict";
// Windows-only: a language server installed by npm is a .cmd shim. The registry
// must find it through PATHEXT and the client must launch it through cmd.exe,
// end to end through a live definition request.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createLspAdapter } = require("../src/lsp-adapter.js");
const { serverRegistry } = require("../src/lsp-server-registry.js");
const { tmpFixture } = require("./helpers/tmp-fixture");

if (process.platform !== "win32") {
  console.log("lsp windows tests skipped (not Windows)");
  process.exit(0);
}

// A minimal LSP server: initialize, didOpen, definition -> helper.ts line 1, shutdown/exit.
const SERVER = `
let buffer = Buffer.alloc(0);
const send = (message) => { const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", ...message })); process.stdout.write("Content-Length: " + body.length + "\\r\\n\\r\\n"); process.stdout.write(body); };
process.stdin.on("data", (chunk) => {
  buffer = Buffer.concat([buffer, chunk]);
  for (;;) {
    const header = buffer.indexOf("\\r\\n\\r\\n"); if (header < 0) return;
    const length = Number(/Content-Length: (\\d+)/i.exec(buffer.slice(0, header).toString())[1]);
    if (buffer.length < header + 4 + length) return;
    const message = JSON.parse(buffer.slice(header + 4, header + 4 + length).toString());
    buffer = buffer.slice(header + 4 + length);
    if (message.method === "initialize") send({ id: message.id, result: { capabilities: { definitionProvider: true }, serverInfo: { name: "fake-cmd-server" } } });
    else if (message.method === "textDocument/definition") {
      const uri = message.params.textDocument.uri.replace(/main\\.ts$/, "helper.ts");
      send({ id: message.id, result: [{ uri, range: { start: { line: 0, character: 16 }, end: { line: 0, character: 23 } } }] });
    } else if (message.method === "shutdown") send({ id: message.id, result: null });
    else if (message.method === "exit") process.exit(0);
    else if (message.id !== undefined) send({ id: message.id, result: null });
  }
});
`;

(async () => {
  const tmp = tmpFixture("pi-lsp-win-");
  const bin = path.join(tmp, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "server.js"), SERVER);
  // The npm shim shape: a .cmd forwarding %* to node and a script.
  fs.writeFileSync(path.join(bin, "typescript-language-server.cmd"), `@"${process.execPath}" "%~dp0server.js" %*\r\n`);
  const env = { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH || ""}` };

  const registry = serverRegistry(env);
  const ts = registry.status().find((entry) => entry.id === "typescript-language-server");
  assert.equal(ts.found, true, "the .cmd server is found through PATHEXT");
  assert.match(ts.path, /typescript-language-server\.cmd$/i);

  const project = path.join(tmp, "project");
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(project, "helper.ts"), "export function doubled(value: number) { return value * 2; }\n");
  fs.writeFileSync(path.join(project, "main.ts"), 'import { doubled } from "./helper";\nconst answer = doubled(21);\n');
  const adapter = createLspAdapter({ live: true, timeoutMs: 15000, registry });
  try {
    const { details } = await adapter.definition({ cwd: project }, { path: project, file: "main.ts", line: 2, column: 16, symbol: "doubled" });
    assert.equal(details.backend, "live-lsp", JSON.stringify(details).slice(0, 600));
    assert.equal(details.definitions[0].file, "helper.ts", "the file URI maps back to a project-relative path");
    assert.equal(details.definitions[0].range.startLine, 1);
  } finally {
    await adapter.closeAll();
  }
  console.log("lsp windows tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
