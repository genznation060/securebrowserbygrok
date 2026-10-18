import assert from "node:assert/strict";
import test from "node:test";
import { defaultLabPolicy, evaluate, runSpecs } from "./securebrowse-policy.ts";

test("lab specs pass against the sample allowlist", () => {
  const results = runSpecs(defaultLabPolicy());
  const failed = results.filter((item) => !item.passed).map((item) => item.name);
  assert.deepEqual(failed, []);
});

test("gesture is irrelevant and external open is impossible", () => {
  const policy = defaultLabPolicy();
  const allowed = evaluate("https://en.wikipedia.org/wiki/Android", policy, "main");
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.openExternally, false);
  const blocked = evaluate("https://evil.example", policy, "main");
  assert.equal(blocked.allowed, false);
  assert.equal(blocked.host, "evil.example");
});
