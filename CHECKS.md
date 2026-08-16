# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `yarn.auth-token-inline` | High | Registry auth token committed in Yarn config |
| `yarn.checksum-ignored` | High | Lockfile integrity verification weakened or bypassed |
| `yarn.docker-missing-patches` | High | A container stage copies a patched Yarn lockfile and runs `yarn install` without copying the referenced patch artifacts |
| `yarn.http-registry` | High | Registry or resolved tarball URLs over plain HTTP |
| `yarn.missing-lockfile` | Medium | Yarn project without a committed `yarn.lock` |
| `yarn.mutable-resolution` | Medium | Dependencies resolved to mutable VCS refs |
| `yarn.strict-ssl-disabled` | High | TLS certificate verification disabled for registry traffic |
