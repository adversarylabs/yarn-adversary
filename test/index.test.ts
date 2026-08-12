import assert from "node:assert/strict";
import test from "node:test";
import { createAdversaryRunEnvelope } from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";

const fixture = (name: string) => new URL(`../fixtures/${name}`, import.meta.url).pathname;
const review = (name: string, raw = false) => createApp().run({ input: { source: { path: fixture(name) } }, includeRawObservations: raw });
const ruleCases = [
  { key: "docker-missing-patches", id: "yarn.docker-missing-patches" },
  { key: "http-registry", id: "yarn.http-registry" },
  { key: "strict-ssl-disabled", id: "yarn.strict-ssl-disabled" },
  { key: "checksum-ignored", id: "yarn.checksum-ignored" },
  { key: "auth-token-inline", id: "yarn.auth-token-inline" },
  { key: "mutable-resolution", id: "yarn.mutable-resolution" },
  { key: "missing-lockfile", id: "yarn.missing-lockfile" },
];

test("every initial rule has focused vulnerable and clean coverage", async () => {
  for (const rule of ruleCases) {
    const vulnerable = await review(`rules/${rule.key}/vulnerable`, true);
    assert.equal(vulnerable.findings.some((finding) => finding.ruleId === rule.id), true, `${rule.id} did not detect its vulnerable fixture`);
    assert.equal(vulnerable.rawObservations?.every((item) => item.location?.file !== undefined), true);
    const clean = await review(`rules/${rule.key}/clean`);
    assert.equal(clean.findings.some((finding) => finding.ruleId === rule.id), false, `${rule.id} flagged its clean fixture`);
  }
});

test("missing patch finding identifies the install and referenced artifact", async () => {
  const output = await review("rules/docker-missing-patches/vulnerable", true);
  const observation = output.rawObservations?.find((item) => item.ruleId === "yarn.docker-missing-patches");
  assert.equal(observation?.location?.file, "Dockerfile");
  assert.equal(observation?.location?.line, 5);
  assert.deepEqual(observation?.evidence?.missingPatches, ["ui/.yarn/patches/react-virtualized-npm-9.22.5-be95b8e1a8.patch"]);
  assert.equal(observation?.evidence?.lockfile, "ui/yarn.lock");
});

test("missing patch rule can use unchanged lockfile context for a changed Dockerfile", async () => {
  const output = await createApp().run({
    input: {
      source: { path: fixture("rules/docker-missing-patches/vulnerable") },
      change: {
        type: "diff",
        base_ref: "base",
        head_ref: "head",
        scan_mode: "changed",
        changed_files: ["Dockerfile"],
      },
    },
    includeRawObservations: true,
  });
  assert.equal(output.findings.some((finding) => finding.ruleId === "yarn.docker-missing-patches"), true);
});

test("accepts a repository without applicable configuration", async () => {
  const output = await review("clean");
  assert.deepEqual(output.findings, []);
  assert.equal(output.assessment?.risk, "none");
  assert.equal(output.opinion?.ship, true);
});

test("output ordering and protocol envelope are deterministic", async () => {
  const first = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  const second = await review(`rules/${ruleCases[0]?.key}/vulnerable`, true);
  assert.deepEqual(second, first);
  const envelope = JSON.parse(JSON.stringify(createAdversaryRunEnvelope(first)));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "deps/yarn");
});
