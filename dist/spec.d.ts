import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "yarn";
    readonly displayName: "Yarn";
    readonly description: "Reviews Yarn projects for insecure registries, mutable resolutions, and missing lockfiles.";
    readonly files: ["package.json", "**/package.json", "yarn.lock", ".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml"];
    readonly rules: [{
        readonly id: "yarn.http-registry";
        readonly title: "Yarn uses a plaintext package registry";
        readonly summary: "Yarn uses a plaintext package registry";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Yarn uses a plaintext package registry weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Use an authenticated HTTPS registry.";
        readonly complexity: "small";
        readonly tags: ["security", "http-registry"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml"];
            readonly pattern: {
                readonly pattern: "(?:registry|npmRegistryServer):\\s*[\"']?http:\\/\\/";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "yarn.mutable-resolution";
        readonly title: "Yarn resolution tracks a mutable branch";
        readonly summary: "Yarn resolution tracks a mutable branch";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Yarn resolution tracks a mutable branch weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Pin VCS resolutions to commits.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-resolution"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json"];
            readonly pattern: {
                readonly pattern: "(?:github:|git\\+https:)[^\"']+#(?:main|master|HEAD)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "yarn.missing-lockfile";
        readonly title: "Yarn project has no lockfile";
        readonly summary: "Yarn project has no lockfile";
        readonly category: "supply-chain";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Yarn project has no lockfile weakens an important supply-chain boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Commit yarn.lock.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "missing-lockfile"];
        readonly match: {
            readonly kind: "missing-file";
            readonly triggerFiles: ["package.json", "**/package.json"];
            readonly requiredFiles: ["yarn.lock"];
        };
    }];
};
export {};
