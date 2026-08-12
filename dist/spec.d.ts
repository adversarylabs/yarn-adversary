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
interface DockerMissingPatchesMatch {
    kind: "docker-missing-patches";
    files: string[];
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
    match: ContentMatch | MissingContentMatch | MissingFileMatch | DockerMissingPatchesMatch;
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
    readonly description: "Reviews Yarn projects for unsafe configuration and incomplete dependency-resolution inputs.";
    readonly files: ["package.json", "**/package.json", "yarn.lock", "**/yarn.lock", ".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc", "Dockerfile", "**/Dockerfile", "Dockerfile.*", "**/Dockerfile.*", "*.dockerfile", "**/*.dockerfile", ".yarn/**"];
    readonly rules: [{
        readonly id: "yarn.docker-missing-patches";
        readonly title: "Container install omits Yarn patch artifacts";
        readonly summary: "Container install omits Yarn patch artifacts";
        readonly category: "correctness";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "A Yarn patch referenced by the copied lockfile is an install input; leaving it outside the container stage makes dependency resolution fail before the build starts.";
        readonly impact: "The image build fails with ENOENT when Yarn resolves the patched dependency.";
        readonly recommendation: "Copy the relevant workspace's .yarn/patches directory into the install stage before running yarn install.";
        readonly complexity: "trivial";
        readonly tags: ["correctness", "docker", "patch-protocol"];
        readonly match: {
            readonly kind: "docker-missing-patches";
            readonly files: ["Dockerfile", "**/Dockerfile", "Dockerfile.*", "**/Dockerfile.*", "*.dockerfile", "**/*.dockerfile"];
        };
    }, {
        readonly id: "yarn.http-registry";
        readonly title: "Yarn uses a plaintext package registry";
        readonly summary: "Yarn uses a plaintext package registry";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Non-TLS registry traffic allows credential and tarball interception.";
        readonly impact: "A MITM can substitute package contents during install.";
        readonly recommendation: "Use an authenticated HTTPS registry; regenerate the lockfile so resolved URLs are HTTPS.";
        readonly complexity: "small";
        readonly tags: ["security", "http-registry"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc", "yarn.lock", "**/yarn.lock"];
            readonly pattern: {
                readonly pattern: "(?:registry|npmRegistryServer|resolved)\\s*[:=]\\s*[\"']?http://(?!localhost|127\\.0\\.0\\.1)";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "yarn.strict-ssl-disabled";
        readonly title: "Yarn disables TLS certificate verification";
        readonly summary: "Yarn disables TLS certificate verification";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "enableStrictSsl: false / strict-ssl false converts every install into a MITM opportunity.";
        readonly impact: "Registry responses and credentials can be substituted without detection.";
        readonly recommendation: "Install the corporate CA via caFilePath/cafile instead of disabling verification.";
        readonly complexity: "small";
        readonly tags: ["security", "strict-ssl"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc"];
            readonly pattern: {
                readonly pattern: "(?:enableStrictSsl\\s*:\\s*false|strict-ssl\\s+(?:false|0)|strict-ssl\\s*=\\s*(?:false|0))";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "yarn.checksum-ignored";
        readonly title: "Yarn weakens lockfile integrity verification";
        readonly summary: "Yarn weakens lockfile integrity verification";
        readonly category: "supply-chain";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "checksumBehavior ignore/update lets substituted tarballs install silently.";
        readonly impact: "Lockfile no longer binds installs to verified package contents.";
        readonly recommendation: "Keep default checksum enforcement; fix mismatches by investigating, not ignoring.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "checksum"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc"];
            readonly pattern: {
                readonly pattern: "checksumBehavior\\s*:\\s*(?:ignore|update)\\b";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "yarn.auth-token-inline";
        readonly title: "Registry auth token committed in Yarn config";
        readonly summary: "Registry auth token committed in Yarn config";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "npmAuthToken/npmAuthIdent/_authToken literals in committed rc files are publish/install credentials in git.";
        readonly impact: "Leaked registry credentials enable package publish or private package theft.";
        readonly recommendation: "Interpolate from environment (npmAuthToken: \"${NPM_TOKEN}\"); rotate anything already committed.";
        readonly complexity: "small";
        readonly tags: ["secrets", "auth-token"];
        readonly match: {
            readonly kind: "content";
            readonly files: [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc"];
            readonly pattern: {
                readonly pattern: "(?:npmAuthToken|npmAuthIdent)\\s*:\\s*[\"']?(?!\\$\\{)[^\\s\"'#]{8,}|_authToken\\s*=\\s*(?!\\$\\{)[^\\s\"'#]{8,}";
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
        readonly whyItMatters: "Git branch resolutions re-fetch moving targets — the lockfile stops locking.";
        readonly impact: "Branch force-push supply-chain substitution of dependencies.";
        readonly recommendation: "Pin VCS resolutions to commit SHAs or publish to a registry.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "mutable-resolution"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["package.json", "**/package.json", "yarn.lock", "**/yarn.lock"];
            readonly pattern: {
                readonly pattern: "(?:github:|git\\+https?:|git@)[^\"'\\s]+#(?:main|master|HEAD)\\b";
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
        readonly whyItMatters: "Without yarn.lock installs are non-reproducible and checksum enforcement has nothing to hold onto.";
        readonly impact: "Different machines resolve different dependency trees for the same ranges.";
        readonly recommendation: "Commit yarn.lock; use yarn install --immutable in CI.";
        readonly complexity: "small";
        readonly tags: ["supply-chain", "missing-lockfile"];
        readonly match: {
            readonly kind: "missing-file";
            readonly triggerFiles: [".yarnrc.yml", "**/.yarnrc.yml", "package.json", "**/package.json"];
            readonly requiredFiles: ["yarn.lock", "**/yarn.lock"];
        };
    }];
};
export {};
