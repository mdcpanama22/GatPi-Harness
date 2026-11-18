"use strict";
// Windows ACL check for the queue connection file (POSIX mode bits don't exist there).
const assert = require("node:assert/strict");
const { aclPrincipals, windowsAclIsPrivate } = require("../src/pi-queue/config.js");

const file = "C:\\Users\\Matt\\.config\\pi-queue\\client.env";
const env = { USERNAME: "Matt", USERDOMAIN: "DESKTOP-DLLV325" };
const icacls = (...aces) =>
  `${file} ${aces[0]}\r\n${aces.slice(1).map((ace) => `${" ".repeat(file.length + 1)}${ace}\r\n`).join("")}\r\nSuccessfully processed 1 files; Failed processing 0 files\r\n`;

// Owner only, as written by `icacls <f> /inheritance:r /grant:r %USERNAME%:F`.
assert.deepEqual(aclPrincipals(icacls("DESKTOP-DLLV325\\Matt:(F)"), file), ["DESKTOP-DLLV325\\Matt"]);
assert.equal(windowsAclIsPrivate(aclPrincipals(icacls("DESKTOP-DLLV325\\Matt:(F)"), file), env), true);

// Typical inherited profile ACL: user + SYSTEM + Administrators is private.
const profile = icacls("NT AUTHORITY\\SYSTEM:(I)(F)", "BUILTIN\\Administrators:(I)(F)", "DESKTOP-DLLV325\\Matt:(I)(F)");
assert.deepEqual(aclPrincipals(profile, file), ["NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators", "DESKTOP-DLLV325\\Matt"]);
assert.equal(windowsAclIsPrivate(aclPrincipals(profile, file), env), true);

// Anyone else is rejected.
for (const other of ["Everyone:(R)", "BUILTIN\\Users:(I)(RX)", "NT AUTHORITY\\Authenticated Users:(I)(M)", "OTHERPC\\Robert:(F)"]) {
  assert.equal(windowsAclIsPrivate(aclPrincipals(icacls("DESKTOP-DLLV325\\Matt:(F)", other), file), env), false, `${other} must be rejected`);
}

// Case-insensitive path echo and names; dir-style inheritance flags parse.
assert.deepEqual(aclPrincipals(icacls("desktop-dllv325\\matt:(OI)(CI)(F)").replace(file, file.toLowerCase()), file), ["desktop-dllv325\\matt"]);

// Unparseable or empty output fails closed.
assert.equal(aclPrincipals("Access is denied.\r\n", file), null);
assert.equal(windowsAclIsPrivate(null, env), false);
assert.equal(windowsAclIsPrivate([], env), false);

console.log("pi-queue win32 ACL tests passed");
