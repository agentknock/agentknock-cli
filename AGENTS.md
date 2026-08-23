# Repository workflow

- Branch from `master`; use descriptive, flat branch names without `/`.
- Use signed Conventional Commits: `feat` for features, `fix` for fixes, and `!`
  for breaking changes.
- Open pull requests and use merge commits. Never commit directly to `master`,
  squash, or rebase.
- Release only by merging the release-plz pull request. Never tag or release
  manually.
