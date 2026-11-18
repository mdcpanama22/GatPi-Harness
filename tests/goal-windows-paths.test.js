"use strict";
// The goal runner blocks autonomous next prompts that write outside the repo.
// On Windows the paths are drive paths (C:\...), Git Bash paths (/c/...) or UNC
// paths (\\server\share), not just POSIX /... paths.
const assert = require("node:assert/strict");
const path = require("node:path");
const { isUnsafeNextPrompt } = require("../.pi/extensions/goal/goal-runner.js");

if (process.platform === "win32") {
  const repo = "C:\\Users\\john.doe\\work\\repo";
  const blocked = (prompt) => /outside repo/.test(String(isUnsafeNextPrompt(prompt, repo) || ""));

  // Outside the repo: blocked, in every Windows spelling.
  assert.equal(blocked("write C:\\Users\\john.doe\\other\\file.txt"), true);
  assert.equal(blocked("edit D:/elsewhere/notes.md"), true);
  assert.equal(blocked("create /c/Windows/Temp/x.txt"), true, "Git Bash drive path");
  assert.equal(blocked("delete \\\\server\\share\\data.json"), true, "UNC path");
  assert.equal(blocked(`write ${repo}-outside\\file.txt`), true, "sibling folder with the repo name as prefix");
  assert.equal(blocked("modify c:\\USERS\\john.doe\\work\\other\\a.ts"), true, "drive letter and case differ");

  // Inside the repo (including dotted folder names and different case): allowed.
  assert.equal(isUnsafeNextPrompt(`write ${repo}\\src\\index.ts`, repo), undefined);
  assert.equal(isUnsafeNextPrompt("edit c:\\users\\JOHN.DOE\\work\\repo\\README.md", repo), undefined, "Windows paths are case-insensitive");
  assert.equal(isUnsafeNextPrompt(`create ${repo.replace(/\\/g, "/")}/docs/plan.md`, repo), undefined, "forward slashes inside the repo");
  assert.equal(isUnsafeNextPrompt("edit src\\app.ts and tests\\app.test.ts", repo), undefined, "relative paths");

  // Negated references stay allowed, as on POSIX.
  assert.equal(isUnsafeNextPrompt("do not write C:\\Windows\\System32\\x.dll; inspect logs instead", repo), undefined);
}

// POSIX behaviour is unchanged.
const cwd = process.platform === "win32" ? "C:\\repo" : "/repo";
assert.match(isUnsafeNextPrompt("write /refactor", cwd), /outside repo: \/refactor/);
assert.equal(isUnsafeNextPrompt("do not write /refactor; inspect logs instead", cwd), undefined);
assert.equal(isUnsafeNextPrompt(`edit ${path.join(cwd, "src", "a.ts")}`, cwd), undefined);
console.log("goal-windows-paths tests passed");
