const RC_FILES = [".yarnrc", ".yarnrc.yml", "**/.yarnrc.yml", ".npmrc", "**/.npmrc"];
const LOCK_FILES = ["yarn.lock", "**/yarn.lock"];
const PKG_FILES = ["package.json", "**/package.json"];
const DOCKER_FILES = ["Dockerfile", "**/Dockerfile", "Dockerfile.*", "**/Dockerfile.*", "*.dockerfile", "**/*.dockerfile"];
export const spec = {
    "id": "yarn",
    "displayName": "Yarn",
    "description": "Reviews Yarn projects for unsafe configuration and incomplete dependency-resolution inputs.",
    "files": [...PKG_FILES, ...LOCK_FILES, ...RC_FILES, ...DOCKER_FILES, ".yarn/**"],
    "rules": [
        {
            "id": "yarn.docker-missing-patches",
            "title": "Container install omits Yarn patch artifacts",
            "summary": "Container install omits Yarn patch artifacts",
            "category": "correctness",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "A Yarn patch referenced by the copied lockfile is an install input; leaving it outside the container stage makes dependency resolution fail before the build starts.",
            "impact": "The image build fails with ENOENT when Yarn resolves the patched dependency.",
            "recommendation": "Copy the relevant workspace's .yarn/patches directory into the install stage before running yarn install.",
            "complexity": "trivial",
            "tags": ["correctness", "docker", "patch-protocol"],
            "match": {
                "kind": "docker-missing-patches",
                "files": [...DOCKER_FILES]
            }
        },
        {
            "id": "yarn.http-registry",
            "title": "Yarn uses a plaintext package registry",
            "summary": "Yarn uses a plaintext package registry",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Non-TLS registry traffic allows credential and tarball interception.",
            "impact": "A MITM can substitute package contents during install.",
            "recommendation": "Use an authenticated HTTPS registry; regenerate the lockfile so resolved URLs are HTTPS.",
            "complexity": "small",
            "tags": ["security", "http-registry"],
            "match": {
                "kind": "content",
                "files": [...RC_FILES, ...LOCK_FILES],
                "pattern": {
                    "pattern": "(?:registry|npmRegistryServer|resolved)\\s*[:=]\\s*[\"']?http://(?!localhost|127\\.0\\.0\\.1)",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "yarn.strict-ssl-disabled",
            "title": "Yarn disables TLS certificate verification",
            "summary": "Yarn disables TLS certificate verification",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "enableStrictSsl: false / strict-ssl false converts every install into a MITM opportunity.",
            "impact": "Registry responses and credentials can be substituted without detection.",
            "recommendation": "Install the corporate CA via caFilePath/cafile instead of disabling verification.",
            "complexity": "small",
            "tags": ["security", "strict-ssl"],
            "match": {
                "kind": "content",
                "files": [...RC_FILES],
                "pattern": {
                    "pattern": "(?:enableStrictSsl\\s*:\\s*false|strict-ssl\\s+(?:false|0)|strict-ssl\\s*=\\s*(?:false|0))",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "yarn.checksum-ignored",
            "title": "Yarn weakens lockfile integrity verification",
            "summary": "Yarn weakens lockfile integrity verification",
            "category": "supply-chain",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "checksumBehavior ignore/update lets substituted tarballs install silently.",
            "impact": "Lockfile no longer binds installs to verified package contents.",
            "recommendation": "Keep default checksum enforcement; fix mismatches by investigating, not ignoring.",
            "complexity": "small",
            "tags": ["supply-chain", "checksum"],
            "match": {
                "kind": "content",
                "files": [...RC_FILES],
                "pattern": {
                    "pattern": "checksumBehavior\\s*:\\s*(?:ignore|update)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "yarn.auth-token-inline",
            "title": "Registry auth token committed in Yarn config",
            "summary": "Registry auth token committed in Yarn config",
            "category": "secrets",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "npmAuthToken/npmAuthIdent/_authToken literals in committed rc files are publish/install credentials in git.",
            "impact": "Leaked registry credentials enable package publish or private package theft.",
            "recommendation": "Interpolate from environment (npmAuthToken: \"${NPM_TOKEN}\"); rotate anything already committed.",
            "complexity": "small",
            "tags": ["secrets", "auth-token"],
            "match": {
                "kind": "content",
                "files": [...RC_FILES],
                "pattern": {
                    "pattern": "(?:npmAuthToken|npmAuthIdent)\\s*:\\s*[\"']?(?!\\$\\{)[^\\s\"'#]{8,}|_authToken\\s*=\\s*(?!\\$\\{)[^\\s\"'#]{8,}",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "yarn.mutable-resolution",
            "title": "Yarn resolution tracks a mutable branch",
            "summary": "Yarn resolution tracks a mutable branch",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Git branch resolutions re-fetch moving targets — the lockfile stops locking.",
            "impact": "Branch force-push supply-chain substitution of dependencies.",
            "recommendation": "Pin VCS resolutions to commit SHAs or publish to a registry.",
            "complexity": "small",
            "tags": ["supply-chain", "mutable-resolution"],
            "match": {
                "kind": "content",
                "files": [...PKG_FILES, ...LOCK_FILES],
                "pattern": {
                    "pattern": "(?:github:|git\\+https?:|git@)[^\"'\\s]+#(?:main|master|HEAD)\\b",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "yarn.missing-lockfile",
            "title": "Yarn project has no lockfile",
            "summary": "Yarn project has no lockfile",
            "category": "supply-chain",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "Without yarn.lock installs are non-reproducible and checksum enforcement has nothing to hold onto.",
            "impact": "Different machines resolve different dependency trees for the same ranges.",
            "recommendation": "Commit yarn.lock; use yarn install --immutable in CI.",
            "complexity": "small",
            "tags": ["supply-chain", "missing-lockfile"],
            "match": {
                "kind": "missing-file",
                "triggerFiles": [".yarnrc.yml", "**/.yarnrc.yml", "package.json", "**/package.json"],
                "requiredFiles": ["yarn.lock", "**/yarn.lock"]
            }
        }
    ]
};
