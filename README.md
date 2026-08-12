# Yarn adversary

Reviews Yarn projects for insecure registries, mutable resolutions, and missing lockfiles.

## Checks

- **Yarn uses a plaintext package registry:** Use an authenticated HTTPS registry.
- **Container install omits Yarn patch artifacts:** Copy the referenced `.yarn/patches` content before installing.
- **Yarn resolution tracks a mutable branch:** Pin VCS resolutions to commits.
- **Yarn project has no lockfile:** Commit yarn.lock.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the yarn adversary when changes include `yarn.lock` or `**/yarn.lock`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
