import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated Yarn config edit does not surface a legacy TLS finding", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, ".yarnrc.yml"), yarnConfig("new diagnostic"));

  const result = await changedReview(repo, [".yarnrc.yml"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "yarn.strict-ssl-disabled"),
    false,
  );
});

test("an added Yarn config remains fully eligible", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, ".npmrc"), "strict-ssl=false\n");

  const result = await changedReview(repo, [".npmrc"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "yarn.strict-ssl-disabled"),
    true,
  );
});

test("an unchanged first occurrence does not hide a later changed occurrence", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, ".yarnrc.yml"), twoRegistries("https"));
  await execute("git", ["add", ".yarnrc.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "registry fixture"], { cwd: repo });
  await writeFile(join(repo, ".yarnrc.yml"), twoRegistries("http"));

  const result = await changedReview(repo, [".yarnrc.yml"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "yarn.http-registry",
  );
  assert.equal(observation?.location?.line, 2);
  assert.match(observation?.location?.snippet ?? "", /http:\/\/packages\.example\.com/);
});

test("an unrelated Dockerfile edit does not re-emit a legacy missing-patch pair", async () => {
  const repo = await repositoryWithPatchInputs(false);
  await writeFile(join(repo, "Dockerfile"), dockerfile(false, "new diagnostic"));

  const result = await changedReview(repo, ["Dockerfile"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "yarn.docker-missing-patches"),
    false,
  );
});

test("a changed lockfile COPY uses unchanged install and package context", async () => {
  const repo = await repositoryWithPatchInputs(true);
  await writeFile(join(repo, "Dockerfile"), dockerfile(false, "fixture"));

  const result = await changedReview(repo, ["Dockerfile"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "yarn.docker-missing-patches",
  );
  assert.equal(observation?.location?.line, 5);
  assert.equal(observation?.location?.snippet, "COPY ui/package.json package.json");
  assert.equal(observation?.evidence?.installLine, 6);
});

async function repositoryWithLegacyConfig(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "yarn-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, ".yarnrc.yml"), yarnConfig("old diagnostic"));
  await execute("git", ["add", ".yarnrc.yml"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

async function repositoryWithPatchInputs(copyPatches: boolean): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "yarn-docker-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await mkdir(join(repo, "ui/.yarn/patches"), { recursive: true });
  await writeFile(join(repo, "ui/package.json"), "{}\n");
  await writeFile(
    join(repo, "ui/yarn.lock"),
    'resolution: "pkg@patch:pkg@npm%3A1.0.0#./.yarn/patches/pkg.patch"\n',
  );
  await writeFile(join(repo, "ui/.yarn/patches/pkg.patch"), "patch\n");
  await writeFile(join(repo, "Dockerfile"), dockerfile(copyPatches, "fixture"));
  await execute("git", ["add", "."], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function yarnConfig(diagnostic: string): string {
  return `enableStrictSsl: false
diagnostic: ${JSON.stringify(diagnostic)}
`;
}

function twoRegistries(secondScheme: string): string {
  return `npmRegistryServer: http://legacy.example.com
registry: ${secondScheme}://packages.example.com
`;
}

function dockerfile(copyPatches: boolean, diagnostic: string): string {
  return `FROM node:22
WORKDIR /app
ENV DIAGNOSTIC=${JSON.stringify(diagnostic)}
COPY ui/yarn.lock yarn.lock
${copyPatches ? "COPY ui/.yarn/patches .yarn/patches" : "COPY ui/package.json package.json"}
RUN yarn install --immutable
`;
}

async function changedReview(
  repoPath: string,
  changedFiles: string[],
  includeRawObservations = false,
) {
  return createApp().run({
    includeRawObservations,
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
