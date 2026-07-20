# Yarn adversary

Reviews Yarn projects for insecure registries, mutable resolutions, and missing lockfiles.

## Checks

- **Yarn uses a plaintext package registry:** Use an authenticated HTTPS registry.
- **Yarn resolution tracks a mutable branch:** Pin VCS resolutions to commits.
- **Yarn project has no lockfile:** Commit yarn.lock.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
