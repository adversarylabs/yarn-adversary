import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { basename, dirname, join, posix, sep } from "node:path";
import { promisify } from "node:util";
import { type RuleContext } from "@adversarylabs/sdk";
import { observationFor } from "./rules.js";
import { spec, type MatchExpression, type RuleSpec } from "./spec.js";

const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);

interface SourceFile {
  path: string;
  source: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}
interface Detection { rule: RuleSpec; file: string; line: number; snippet: string; label: string; data: Record<string, unknown> }

export async function analyzeRepository(ctx: RuleContext): Promise<void> {
  // Full tree for existence/context checks; content uses CLI/SDK review scope.
  const allPaths = await walk(ctx.repoPath);
  const scoped = await ctx.loadInScopeSources({
    include: (path) =>
      !path.split("/").some((segment) => SKIPPED.has(segment)) &&
      spec.files.some((glob) => matchesGlob(path, glob)),
    limit: MAX_FILES,
  });
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: SourceFile[] = [];
  for (const file of scoped) {
    if (wholeTarget || file.status === "repository") {
      sources.push({
        path: file.path,
        source: file.content,
        changedLines: new Set<number>(),
        status: "repository",
      });
      continue;
    }

    const change = await changedSource(ctx, file.path);
    sources.push({
      path: file.path,
      source: file.content,
      changedLines: change.changedLines,
      status: change.status,
    });
  }
  ctx.summary.files_scanned = sources.length;

  const detections = (await Promise.all(spec.rules.map((rule) => evaluate(rule, sources, allPaths, ctx.repoPath)))).flat();
  detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
  for (const detection of detections) ctx.observe(observationFor(detection));

  if (sources.length > 0 && detections.length === 0) {
    ctx.review.positive({
      key: `${spec.id}.reviewed`,
      summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
      evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
    });
  }
}

async function evaluate(rule: RuleSpec, sources: SourceFile[], allPaths: string[], repoPath: string): Promise<Detection[]> {
  const match = rule.match;
  if (match.kind === "missing-file") {
    const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
    const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
    if (triggers.length === 0 || required) return [];
    return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
  }

  const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
  if (match.kind === "docker-missing-patches") {
    return (await Promise.all(matchingSources.map((file) => findDockerMissingPatches(rule, file, allPaths, repoPath)))).flat();
  }
  if (match.kind === "missing-content") {
    return matchingSources.flatMap((file) => {
      if (!test(file.source, match.trigger) || test(file.source, match.required)) return [];
      const location = locate(file, match.trigger);
      if (location === undefined) return [];
      return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
    });
  }

  return matchingSources.flatMap((file) => {
    if (!match.requires.every((pattern) => test(file.source, pattern))) return [];
    const location = locate(file, match.pattern);
    if (location === undefined) return [];
    return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
  });
}

interface DockerInstruction { command: string; value: string; line: number; endLine: number; snippet: string }
interface DockerCopy { source: string; target: string; external: boolean; line: number; endLine: number }

async function findDockerMissingPatches(rule: RuleSpec, dockerfile: SourceFile, allPaths: string[], repoPath: string): Promise<Detection[]> {
  const instructions = dockerInstructions(dockerfile.source);
  let workdir = "/";
  let copies: DockerCopy[] = [];
  const lockfiles = new Map<string, { source: string; patches: string[]; line: number; endLine: number }>();
  const detections: Detection[] = [];

  for (const instruction of instructions) {
    if (instruction.command === "FROM") {
      workdir = "/";
      copies = [];
      lockfiles.clear();
      continue;
    }
    if (instruction.command === "WORKDIR") {
      workdir = containerPath(workdir, instruction.value.trim());
      continue;
    }
    if (instruction.command === "COPY" || instruction.command === "ADD") {
      for (const copy of parseDockerCopies(
        instruction.value,
        workdir,
        instruction.line,
        instruction.endLine,
      )) {
        copies.push(copy);
        if (copy.external) continue;
        for (const sourcePath of allPaths.filter((path) => basename(path) === "yarn.lock" && copyContainsRepositoryPath(copy, path))) {
          try {
            const lockSource = await readFile(join(repoPath, sourcePath), "utf8");
            const patches = localPatchPaths(lockSource, sourcePath).filter((path) => allPaths.includes(path));
            lockfiles.set(copyTargetForRepositoryPath(copy, sourcePath), {
              source: sourcePath,
              patches,
              line: instruction.line,
              endLine: instruction.endLine,
            });
          } catch {
            // A scoped Dockerfile may reference a generated or context-external lockfile.
          }
        }
      }
      continue;
    }
    if (instruction.command !== "RUN" || !/(?:^|[;&|]\s*)yarn\s+install\b/.test(instruction.value)) continue;
    const lock = lockfiles.get(posix.join(workdir, "yarn.lock"));
    if (!lock || lock.patches.length === 0) continue;
    const missing = lock.patches.filter((patch) => !copyDeliversPatch(copies, patch, posix.join(workdir, ".yarn/patches", basename(patch))));
    if (missing.length === 0) continue;
    const line = eligibleLine(dockerfile, instruction.line, instruction.endLine)
      ?? eligibleLine(dockerfile, lock.line, lock.endLine)
      ?? copies.map((copy) => eligibleLine(dockerfile, copy.line, copy.endLine))
        .find((candidate): candidate is number => candidate !== undefined);
    if (line === undefined) continue;
    detections.push({
      rule,
      file: dockerfile.path,
      line,
      snippet: dockerfile.source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "",
      label: `yarn install cannot access ${missing.length === 1 ? basename(missing[0] ?? "patch") : `${missing.length} referenced patches`}`,
      data: { lockfile: lock.source, missingPatches: missing, installLine: instruction.line },
    });
  }
  return detections;
}

function dockerInstructions(source: string): DockerInstruction[] {
  const lines = source.split(/\r?\n/);
  const instructions: DockerInstruction[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const start = index;
    const parts = [lines[index] ?? ""];
    while (/\\\s*$/.test(parts[parts.length - 1] ?? "") && index + 1 < lines.length) parts.push(lines[++index] ?? "");
    const logical = parts.join("\n");
    const match = /^\s*([A-Za-z]+)\s+([\s\S]*)$/.exec(logical);
    if (!match || logical.trimStart().startsWith("#")) continue;
    instructions.push({
      command: (match[1] ?? "").toUpperCase(),
      value: (match[2] ?? "").replace(/\\\s*\n/g, " "),
      line: start + 1,
      endLine: index + 1,
      snippet: (lines[start] ?? "").trim().slice(0, 240),
    });
  }
  return instructions;
}

function parseDockerCopies(
  value: string,
  workdir: string,
  line: number,
  endLine: number,
): DockerCopy[] {
  let input = value.trim();
  let external = false;
  while (input.startsWith("--")) {
    const option = /^(--[^\s]+)\s*/.exec(input)?.[1];
    if (!option) break;
    if (option.startsWith("--from=")) external = true;
    input = input.slice(option.length).trimStart();
  }
  let paths: string[] = [];
  if (input.startsWith("[")) {
    try { paths = JSON.parse(input) as string[]; } catch { return []; }
  } else {
    paths = input.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((part) => part.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, "$1$2")) ?? [];
  }
  if (paths.length < 2) return [];
  const destination = paths.at(-1) ?? "";
  const sources = paths.slice(0, -1);
  const destinationIsDirectory = sources.length > 1 || destination.endsWith("/") || destination === ".";
  const targetBase = containerPath(workdir, destination);
  return sources.map((source) => ({
    source: repoPathFromDocker(source),
    target: posix.normalize(destinationIsDirectory ? posix.join(targetBase, basename(repoPathFromDocker(source))) : targetBase),
    external,
    line,
    endLine,
  }));
}

function repoPathFromDocker(path: string): string {
  return posix.normalize(path.replace(/^\/+/, "").replace(/^\.\//, ""));
}

function containerPath(workdir: string, path: string): string {
  return posix.normalize(path.startsWith("/") ? path : posix.join(workdir, path));
}

function localPatchPaths(lockSource: string, lockfile: string): string[] {
  const paths = new Set<string>();
  const pattern = /patch:[^\r\n]*?#(?:~\/|\.\/)?([^\s"',:]+\.patch)\b/g;
  for (const match of lockSource.matchAll(pattern)) {
    const relative = decodeURIComponent(match[1] ?? "");
    if (!relative) continue;
    paths.add(posix.normalize(posix.join(dirname(lockfile), relative)));
  }
  return [...paths].sort();
}

function copyDeliversPatch(copies: DockerCopy[], repositoryPatch: string, expectedTarget: string): boolean {
  return copies.some((copy) => {
    if (copy.external) return copy.target === expectedTarget || expectedTarget.startsWith(`${copy.target}/`);
    return copyContainsRepositoryPath(copy, repositoryPatch) && copyTargetForRepositoryPath(copy, repositoryPatch) === expectedTarget;
  });
}

function copyContainsRepositoryPath(copy: DockerCopy, repositoryPath: string): boolean {
  return repositoryPath === copy.source || copy.source === "." || repositoryPath.startsWith(`${copy.source}/`);
}

function copyTargetForRepositoryPath(copy: DockerCopy, repositoryPath: string): string {
  return repositoryPath === copy.source ? copy.target : posix.join(copy.target, posix.relative(copy.source, repositoryPath));
}

function test(source: string, expression: MatchExpression): boolean {
  return new RegExp(expression.pattern, expression.flags).test(source);
}

function locate(file: SourceFile, expression: MatchExpression): { line: number; snippet: string } | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  const pattern = new RegExp(expression.pattern, flags);
  const sourceLines = file.source.split(/\r?\n/);
  for (const match of file.source.matchAll(pattern)) {
    if (match.index === undefined) continue;
    const startLine = file.source.slice(0, match.index).split(/\r?\n/).length;
    const endLine = startLine + (match[0]?.match(/\r?\n/g)?.length ?? 0);
    const line = eligibleLine(file, startLine, endLine);
    if (line === undefined) continue;
    return { line, snippet: sourceLines[line - 1]?.trim().slice(0, 240) ?? "" };
  }
  return undefined;
}

function eligibleLine(file: SourceFile, startLine: number, endLine: number): number | undefined {
  if (file.status === "repository" || file.status === "added") return startLine;
  for (let line = startLine; line <= endLine; line += 1) {
    if (file.changedLines.has(line)) return line;
  }
  return undefined;
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceFile, "changedLines" | "status">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  return { changedLines: changedLineNumbers(patch), status: "modified" };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

async function walk(root: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(relative: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    const entries = await readdir(join(root, relative), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const path = relative ? join(relative, entry.name) : entry.name;
      if (entry.isDirectory() && !SKIPPED.has(entry.name)) await visit(path);
      else if (entry.isFile()) files.push(path.split(sep).join("/"));
    }
  }
  await visit("");
  return files.sort();
}

function matchesGlob(path: string, glob: string): boolean {
  let pattern = "^";
  for (let index = 0; index < glob.length; index += 1) {
    const character = glob[index];
    if (character === "*" && glob[index + 1] === "*") {
      if (glob[index + 2] === "/") { pattern += "(?:.*/)?"; index += 2; }
      else { pattern += ".*"; index += 1; }
    } else if (character === "*") pattern += "[^/]*";
    else if (character === "?") pattern += "[^/]";
    else pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
  }
  return new RegExp(`${pattern}$`, "i").test(path);
}
