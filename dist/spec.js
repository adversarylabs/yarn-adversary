export const spec = {
    "id": "yarn",
    "displayName": "Yarn",
    "description": "Reviews Yarn projects for insecure registries, mutable resolutions, and missing lockfiles.",
    "files": [
        "package.json",
        "**/package.json",
        "yarn.lock",
        ".yarnrc",
        ".yarnrc.yml",
        "**/.yarnrc.yml"
    ],
    "rules": [
        {
            "id": "yarn.http-registry",
            "title": "Yarn uses a plaintext package registry",
            "summary": "Yarn uses a plaintext package registry",
            "category": "security",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "Yarn uses a plaintext package registry weakens an important security boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Use an authenticated HTTPS registry.",
            "complexity": "small",
            "tags": [
                "security",
                "http-registry"
            ],
            "match": {
                "kind": "content",
                "files": [
                    ".yarnrc",
                    ".yarnrc.yml",
                    "**/.yarnrc.yml"
                ],
                "pattern": {
                    "pattern": "(?:registry|npmRegistryServer):\\s*[\"']?http:\\/\\/",
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
            "whyItMatters": "Yarn resolution tracks a mutable branch weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Pin VCS resolutions to commits.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "mutable-resolution"
            ],
            "match": {
                "kind": "content",
                "files": [
                    "package.json",
                    "**/package.json"
                ],
                "pattern": {
                    "pattern": "(?:github:|git\\+https:)[^\"']+#(?:main|master|HEAD)",
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
            "whyItMatters": "Yarn project has no lockfile weakens an important supply-chain boundary.",
            "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
            "recommendation": "Commit yarn.lock.",
            "complexity": "small",
            "tags": [
                "supply-chain",
                "missing-lockfile"
            ],
            "match": {
                "kind": "missing-file",
                "triggerFiles": [
                    "package.json",
                    "**/package.json"
                ],
                "requiredFiles": [
                    "yarn.lock"
                ]
            }
        }
    ]
};
