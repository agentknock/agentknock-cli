#!/bin/sh

set -eu

repository_root=$(unset CDPATH; cd -- "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)
dist_dir=$test_dir/dist
npm_dir=$test_dir/npm
install_dir=$test_dir/install

cleanup() {
	rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

# Keep the variables literal in the generated fixture script.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
	'printf "%s\n" "${AGENTKNOCK_NPM_TEST:-}" "$@"' \
	> "$test_dir/agentknock"
chmod 0755 "$test_dir/agentknock"

mkdir -p "$dist_dir"
for target in \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-musl \
	aarch64-apple-darwin; do
	archive=agentknock-$target.tar.gz
	tar --create --gzip --file="$dist_dir/$archive" \
		--directory="$test_dir" agentknock
	(
		cd "$dist_dir"
		sha256 "$archive" > "$archive.sha256"
	)
done

"$repository_root/scripts/package-npm" "$dist_dir" "$npm_dir" >/dev/null
npm install --ignore-scripts --no-audit --no-fund --prefix "$install_dir" \
	"$npm_dir"/agentknock-*.tgz --loglevel=error

actual=$(AGENTKNOCK_NPM_TEST=preserved \
	"$install_dir/node_modules/.bin/agentknock" first "two words")
expected=$(printf '%s\n' preserved first "two words")
[ "$actual" = "$expected" ] || {
	printf 'npm launcher did not preserve its environment and arguments\n' >&2
	exit 1
}

printf 'npm package tests passed\n'
