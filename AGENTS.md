# Repository workflow

- Branch from `master`; use descriptive, flat branch names without `/`.
- Use signed Conventional Commits. Use `feat` for new functionality that does
  not affect existing clients when unused. Use `fix` for backward-compatible
  code changes that correct or modify existing functionality without adding a
  feature. Use `!` only when a change to existing functionality breaks existing
  clients. If a change does not alter the produced binaries, use neither `feat`
  nor `fix`.
- Rebase feature branches onto `origin/master` and force-push with lease. Never
  merge `master` into a feature branch.
- Open pull requests and merge them with merge commits. Never commit directly
  to `master`, squash pull requests, or rebase-merge pull requests.
- Release only by merging the release-plz pull request. Never tag or release
  manually.
