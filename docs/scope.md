# deps/yarn — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `yarn`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Yarn

## Mission

Review Yarn for insecure registries, mutable resolutions, and missing lockfiles.

## In scope (fair miss if humans raised it and we did not)

- Insecure registries
- Mutable resolutions
- Missing yarn.lock
- Container stages that install from patched Yarn lockfiles without the referenced patch artifacts

## Out of scope (not a miss for this adversary)

- npm-specific
- App logic

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
