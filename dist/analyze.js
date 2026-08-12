import { readFile, readdir } from "node:fs/promises";
import { basename, dirname, join, posix, sep } from "node:path";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const sources = scoped.map((file) => ({ path: file.path, source: file.content }));
    ctx.summary.files_scanned = sources.length;
    const detections = (await Promise.all(spec.rules.map((rule) => evaluate(rule, sources, allPaths, ctx.repoPath)))).flat();
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
async function evaluate(rule, sources, allPaths, repoPath) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "docker-missing-patches") {
        return (await Promise.all(matchingSources.map((file) => findDockerMissingPatches(rule, file, allPaths, repoPath)))).flat();
    }
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locate(file.source, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locate(file.source, match.pattern);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
async function findDockerMissingPatches(rule, dockerfile, allPaths, repoPath) {
    const instructions = dockerInstructions(dockerfile.source);
    let workdir = "/";
    let copies = [];
    const lockfiles = new Map();
    const detections = [];
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
            for (const copy of parseDockerCopies(instruction.value, workdir)) {
                copies.push(copy);
                if (copy.external)
                    continue;
                for (const sourcePath of allPaths.filter((path) => basename(path) === "yarn.lock" && copyContainsRepositoryPath(copy, path))) {
                    try {
                        const lockSource = await readFile(join(repoPath, sourcePath), "utf8");
                        const patches = localPatchPaths(lockSource, sourcePath).filter((path) => allPaths.includes(path));
                        lockfiles.set(copyTargetForRepositoryPath(copy, sourcePath), { source: sourcePath, patches });
                    }
                    catch {
                        // A scoped Dockerfile may reference a generated or context-external lockfile.
                    }
                }
            }
            continue;
        }
        if (instruction.command !== "RUN" || !/(?:^|[;&|]\s*)yarn\s+install\b/.test(instruction.value))
            continue;
        const lock = lockfiles.get(posix.join(workdir, "yarn.lock"));
        if (!lock || lock.patches.length === 0)
            continue;
        const missing = lock.patches.filter((patch) => !copyDeliversPatch(copies, patch, posix.join(workdir, ".yarn/patches", basename(patch))));
        if (missing.length === 0)
            continue;
        detections.push({
            rule,
            file: dockerfile.path,
            line: instruction.line,
            snippet: instruction.snippet,
            label: `yarn install cannot access ${missing.length === 1 ? basename(missing[0] ?? "patch") : `${missing.length} referenced patches`}`,
            data: { lockfile: lock.source, missingPatches: missing },
        });
    }
    return detections;
}
function dockerInstructions(source) {
    const lines = source.split(/\r?\n/);
    const instructions = [];
    for (let index = 0; index < lines.length; index += 1) {
        const start = index;
        const parts = [lines[index] ?? ""];
        while (/\\\s*$/.test(parts[parts.length - 1] ?? "") && index + 1 < lines.length)
            parts.push(lines[++index] ?? "");
        const logical = parts.join("\n");
        const match = /^\s*([A-Za-z]+)\s+([\s\S]*)$/.exec(logical);
        if (!match || logical.trimStart().startsWith("#"))
            continue;
        instructions.push({ command: (match[1] ?? "").toUpperCase(), value: (match[2] ?? "").replace(/\\\s*\n/g, " "), line: start + 1, snippet: (lines[start] ?? "").trim().slice(0, 240) });
    }
    return instructions;
}
function parseDockerCopies(value, workdir) {
    let input = value.trim();
    let external = false;
    while (input.startsWith("--")) {
        const option = /^(--[^\s]+)\s*/.exec(input)?.[1];
        if (!option)
            break;
        if (option.startsWith("--from="))
            external = true;
        input = input.slice(option.length).trimStart();
    }
    let paths = [];
    if (input.startsWith("[")) {
        try {
            paths = JSON.parse(input);
        }
        catch {
            return [];
        }
    }
    else {
        paths = input.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)?.map((part) => part.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, "$1$2")) ?? [];
    }
    if (paths.length < 2)
        return [];
    const destination = paths.at(-1) ?? "";
    const sources = paths.slice(0, -1);
    const destinationIsDirectory = sources.length > 1 || destination.endsWith("/") || destination === ".";
    const targetBase = containerPath(workdir, destination);
    return sources.map((source) => ({
        source: repoPathFromDocker(source),
        target: posix.normalize(destinationIsDirectory ? posix.join(targetBase, basename(repoPathFromDocker(source))) : targetBase),
        external,
    }));
}
function repoPathFromDocker(path) {
    return posix.normalize(path.replace(/^\/+/, "").replace(/^\.\//, ""));
}
function containerPath(workdir, path) {
    return posix.normalize(path.startsWith("/") ? path : posix.join(workdir, path));
}
function localPatchPaths(lockSource, lockfile) {
    const paths = new Set();
    const pattern = /patch:[^\r\n]*?#(?:~\/|\.\/)?([^\s"',:]+\.patch)\b/g;
    for (const match of lockSource.matchAll(pattern)) {
        const relative = decodeURIComponent(match[1] ?? "");
        if (!relative)
            continue;
        paths.add(posix.normalize(posix.join(dirname(lockfile), relative)));
    }
    return [...paths].sort();
}
function copyDeliversPatch(copies, repositoryPatch, expectedTarget) {
    return copies.some((copy) => {
        if (copy.external)
            return copy.target === expectedTarget || expectedTarget.startsWith(`${copy.target}/`);
        return copyContainsRepositoryPath(copy, repositoryPatch) && copyTargetForRepositoryPath(copy, repositoryPatch) === expectedTarget;
    });
}
function copyContainsRepositoryPath(copy, repositoryPath) {
    return repositoryPath === copy.source || copy.source === "." || repositoryPath.startsWith(`${copy.source}/`);
}
function copyTargetForRepositoryPath(copy, repositoryPath) {
    return repositoryPath === copy.source ? copy.target : posix.join(copy.target, posix.relative(copy.source, repositoryPath));
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locate(source, expression) {
    const match = new RegExp(expression.pattern, expression.flags).exec(source);
    if (match?.index === undefined)
        return undefined;
    const line = source.slice(0, match.index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
