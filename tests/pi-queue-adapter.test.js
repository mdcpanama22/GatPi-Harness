"use strict";
const { tmpFixture } = require("./helpers/tmp-fixture");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

// Windows has no POSIX mode bits; privacy is the file's ACL (see src/pi-queue/config.js).
const win32 = process.platform === "win32";
const icacls = (...args) => execFileSync("icacls", args, { stdio: "ignore", windowsHide: true });
const loosen = (file) => (win32 ? icacls(file, "/grant", "*S-1-1-0:(R)") : fs.chmodSync(file, 0o644));
// Windows: drop inherited ACEs (temp dirs can carry extra principals) and grant only the user.
const tighten = (file) => {
  if (!win32) return fs.chmodSync(file, 0o600);
  icacls(file, "/remove", "*S-1-1-0");
  icacls(file, "/inheritance:r", "/grant:r", `${process.env.USERNAME}:F`);
};

(async () => {
  const adapter = require("../src/pi-queue-adapter.js");
  assert(!Object.keys(require.cache).some((file) => file.includes(`${path.sep}ioredis${path.sep}`)), "Loading the adapter must not load the Redis client");

  const runtimeRoot = path.join(__dirname, "..", "src", "pi-queue");
  const clientInstalled = fs.existsSync(path.join(runtimeRoot, "node_modules", "ioredis", "package.json"));
  const unconfigured = clientInstalled ? "not-configured" : "not-installed";
  const unconfiguredReason = clientInstalled ? /client\.env/ : /setup-pi-queue/;

  const home = tmpFixture("pi-queue-adapter-");
  try {
    const file = path.join(home, "client.env");
    const env = { HOME: home, PI_QUEUE_ENV: file };
    assert.equal(adapter.queueReadiness({ env: { ...env, PI_QUEUE: "0" } }).outcome, "disabled");
    const missing = adapter.queueReadiness({ env });
    assert.equal(missing.outcome, unconfigured, `A ${clientInstalled ? "installed" : "absent"} client reports ${unconfigured}`);
    assert.equal(missing.ready, false);
    assert.match(missing.reason, unconfiguredReason);
    assert.equal((await adapter.queueQuery("status", {}, { env })).outcome, unconfigured, "Status reports readiness instead of throwing");
    await assert.rejects(adapter.acquireModelSlot({}, { env }), new RegExp(`${unconfigured}.*PI_QUEUE=0`, "s"), "Unconfigured queue blocks the model request with a bypass hint");

    const secret = "s3cret-password-value";
    for (const name of ["ca.crt", "client.crt", "client.key"]) fs.writeFileSync(path.join(home, name), "placeholder\n", { mode: 0o600 });
    const body = `REDIS_HOST=127.0.0.1\nREDIS_PORT=1\nREDIS_USERNAME=queue\nREDIS_PASSWORD=${secret}\nREDIS_CA=${home}/ca.crt\nREDIS_CERT=${home}/client.crt\nREDIS_KEY=${home}/client.key\n`;
    if (!clientInstalled) {
      // Regression: a valid configuration cannot make an absent client ready.
      fs.writeFileSync(file, body, { mode: 0o600 });
      assert.equal(adapter.queueReadiness({ env }).outcome, "not-installed", "The install check takes precedence over a valid configuration");
    } else {
      fs.writeFileSync(file, body, { mode: 0o644 });
      loosen(file); // POSIX: chmod 644 (the mode option is masked by umask). Windows: grant Everyone read.
      const loose = adapter.queueReadiness({ env });
      assert.equal(loose.outcome, "invalid-config", "World-readable credentials are rejected");
      assert(!JSON.stringify(loose).includes(secret));
      await assert.rejects(adapter.acquireModelSlot({}, { env }), (error) => !error.message.includes(secret) && /invalid-config/.test(error.message));

      tighten(file);
      assert.equal(adapter.queueReadiness({ env }).outcome, "ready");
      fs.writeFileSync(file, body.replace(`${home}/ca.crt`, "ca.crt"), { mode: 0o600 });
      assert.equal(adapter.queueReadiness({ env }).outcome, "invalid-config", "Certificate paths must be absolute");

      fs.writeFileSync(file, body, { mode: 0o600 });
      const started = Date.now();
      await assert.rejects(adapter.acquireModelSlot({}, { env }), (error) =>
        /request failed.*not sent.*PI_QUEUE=0/s.test(error.message) && !error.message.includes(secret));
      assert(Date.now() - started < 15_000, "An unreachable broker fails promptly instead of hanging the model request");
    }
    await adapter.closeQueue();
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
  console.log("pi-queue adapter tests passed");
})().catch((error) => { console.error(error); process.exit(1); });
