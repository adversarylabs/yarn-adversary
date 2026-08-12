# Checks — what yarn detects

This file is the **public audit list** of detectors for the **yarn** adversary. High-confidence Yarn-specific supply-chain defects with file:line evidence in `yarn.lock`, `.yarnrc.yml` / `.yarnrc`, and `.yarn/`. Shared `package.json` concerns (lifecycle scripts, dependency ranges, update-automation cooldown) are owned by `npm` — this adversary covers only what Yarn adds.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `yarn.lock` (classic v1 and Berry formats), `.yarnrc.yml` (Berry), `.yarnrc`/`.npmrc` yarn-relevant keys (classic), `.yarn/` directory contents at the metadata level (no tarball deep-scan).

**Precision stance:** Integrity/TLS downgrades fire hard — they are never legitimate in committed config. Lockfile findings distinguish classic vs Berry semantics correctly (different fields, different checksum models) rather than pattern-matching one onto the other.

Public grounding: Yarn Berry configuration docs (`enableStrictSsl`, `checksumBehavior`, `npmAuthToken`), yarn.lock integrity semantics, and the npm-ecosystem supply-chain incident record (which flows through Yarn installs identically).

---

## High

### `yarn.docker-missing-patches`

| | |
| --- | --- |
| **What** | A container stage copies a patched Yarn lockfile and runs `yarn install` without copying the referenced patch artifacts |
| **Why** | Local Yarn patches are dependency-resolution inputs; the install fails with `ENOENT` when the lockfile reaches a stage without them |
| **Looks for** | A Docker stage that copies a `yarn.lock` with a repository-local `patch:` reference, enters that install directory, and runs `yarn install` before the matching patch file or directory is copied there |
| **Stays quiet when** | The lockfile has no local patch; the required file, `.yarn/patches`, or containing project tree reaches the stage; or the lockfile is not used by that install |
| **Public examples** | [Taskcluster’s merged fix](https://github.com/taskcluster/taskcluster/pull/8842), including the failing Yarn `ENOENT` log and the approved patch-directory copy |
| **Remediation** | Copy the relevant workspace’s `.yarn/patches` directory into the install stage before running Yarn |

### `yarn.http-registry`

| | |
| --- | --- |
| **What** | Registry or resolved tarball URLs over plain HTTP |
| **Why** | Non-TLS registry traffic allows credential and tarball interception — a MITM can substitute package contents |
| **Looks for** | `npmRegistryServer: "http://…"` / scoped `npmRegistries` http entries in `.yarnrc.yml`; `registry "http://…"` in classic `.yarnrc`; `resolved "http://…"` entries in `yarn.lock` |
| **Stays quiet when** | HTTPS everywhere; `localhost`/`127.0.0.1` registries (offline mirrors, verdaccio dev) downgrade to low |
| **Public examples** | Yarn registry configuration docs; registry-MITM tarball substitution scenarios |
| **Remediation** | Use an authenticated HTTPS registry; regenerate the lockfile so resolved URLs are HTTPS |

### `yarn.strict-ssl-disabled`

| | |
| --- | --- |
| **What** | TLS certificate verification disabled for registry traffic |
| **Why** | `enableStrictSsl: false` (Berry) / `strict-ssl false` (classic) is the package-manager equivalent of `InsecureSkipVerify` — it converts every install into a MITM opportunity, and it always outlives the corporate-proxy incident that motivated it |
| **Looks for** | `enableStrictSsl: false` in `.yarnrc.yml`; `strict-ssl false` in committed `.yarnrc`/`.npmrc` |
| **Stays quiet when** | Absent/true. No suppression for CI-only files — CI is where interception hurts most |
| **Public examples** | Yarn configuration docs; the recurring “fix the proxy by turning off TLS” anti-pattern |
| **Remediation** | Install the corporate CA via `caFilePath`/`cafile` instead of disabling verification |

### `yarn.checksum-ignored`

| | |
| --- | --- |
| **What** | Lockfile integrity verification weakened or bypassed |
| **Why** | Checksums are the only thing binding the lockfile to actual tarball contents; `checksumBehavior: ignore`/`update` in committed config means a substituted tarball installs silently |
| **Looks for** | `checksumBehavior: ignore` or `update` in `.yarnrc.yml`; `yarn.lock` entries missing `checksum`/`integrity` fields where the format requires them; `--update-checksums` baked into CI install commands |
| **Stays quiet when** | Default (`throw`) behavior; `reset` used interactively (not committed) |
| **Public examples** | Yarn checksumBehavior docs; tarball-substitution attack models |
| **Remediation** | Keep default checksum enforcement; fix mismatches by investigating, not ignoring |

### `yarn.auth-token-inline`

| | |
| --- | --- |
| **What** | Registry auth token committed in Yarn config |
| **Why** | `npmAuthToken`/`npmAuthIdent` literals in `.yarnrc.yml` (or `_authToken` in classic config) are publish/install credentials in git — Yarn-context detection; generic token scanning stays with `security/secrets` |
| **Looks for** | `npmAuthToken:`/`npmAuthIdent:` with literal non-placeholder values in committed `.yarnrc.yml` (top-level or per-registry); classic `_authToken=` literals |
| **Stays quiet when** | `${NPM_TOKEN}`/`${NPM_AUTH_TOKEN}` env interpolation (the documented pattern); values in gitignored local rc files |
| **Public examples** | Yarn docs recommend env interpolation for exactly this reason; leaked-token postmortems |
| **Remediation** | Interpolate from environment (`npmAuthToken: "${NPM_TOKEN}"`); rotate anything already committed |

---

## Medium

### `yarn.mutable-resolution`

| | |
| --- | --- |
| **What** | Dependencies resolved to mutable VCS refs |
| **Why** | `yarn.lock` entries resolving to git branches (or `resolutions:` forcing branch refs) re-fetch moving targets — the lockfile stops locking |
| **Looks for** | Lock entries / `resolutions:` values with git URLs pinned to `#main`/`#master`/no commit; `patch:` sources referencing mutable bases |
| **Stays quiet when** | Full commit SHAs; registry semver resolutions; `patch:` over registry versions with committed patch files |
| **Public examples** | Yarn protocols docs (git:, patch:); branch force-push supply-chain scenarios |
| **Remediation** | Pin VCS resolutions to commit SHAs or publish to a registry |

### `yarn.missing-lockfile`

| | |
| --- | --- |
| **What** | Yarn project without a committed `yarn.lock` |
| **Why** | Installs become non-reproducible; every machine resolves ranges independently — and without a lockfile, checksum enforcement has nothing to hold onto |
| **Looks for** | Yarn markers present (`.yarnrc.yml`, `packageManager: yarn@…`, yarn scripts in CI) with no `yarn.lock` tracked |
| **Stays quiet when** | Lockfile committed. Pure libraries downgrade to low (locks don't ship with publishes); apps and anything with CI deploy signals fire at medium |
| **Public examples** | Yarn lockfile docs; “works on my machine” drift |
| **Remediation** | Commit `yarn.lock`; use `yarn install --immutable` in CI |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| `package.json` lifecycle scripts, dependency ranges | `npm` |
| Update-automation cooldown (Renovate/Dependabot) | `npm` (`auto-update-no-cooldown`) |
| pnpm workspaces/lockfiles | `pnpm` adversary |
| Generic committed secrets | `security/secrets` |
| Node runtime code | `nodejs` / `typescript` / `react` |
