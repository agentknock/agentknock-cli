#!/bin/sh

set -eu

repository_root=$(unset CDPATH; cd -- "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)
package_dir=$test_dir/package
install_dir=$test_dir/install

cleanup() {
	rm -rf -- "$test_dir"
}
trap cleanup EXIT HUP INT TERM

install -D -m 0755 "$repository_root/npm/agentknock.js" \
	"$package_dir/agentknock.js"
install -D -m 0644 "$repository_root/npm/package.json" \
	"$package_dir/package.json"
install -D -m 0644 "$repository_root/README.md" "$package_dir/README.md"
install -D -m 0644 "$repository_root/LICENSE-APACHE" \
	"$package_dir/LICENSE-APACHE"
install -D -m 0644 "$repository_root/LICENSE-MIT" \
	"$package_dir/LICENSE-MIT"

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
	mkdir -p "$package_dir/bin"
	# Keep the variables literal in the generated fixture script.
	# shellcheck disable=SC2016
	printf '%s\n' '#!/bin/sh' \
		'printf "%s\n" "${AGENTKNOCK_NPM_TEST:-}" "$@"' \
		> "$package_dir/bin/agentknock-$target"
	chmod 0755 "$package_dir/bin/agentknock-$target"
done

npm pkg set version=1.2.3 --prefix "$package_dir"
npm pkg delete private --prefix "$package_dir"
npm pack "$package_dir" --ignore-scripts --loglevel=error \
	--pack-destination "$test_dir" >/dev/null
npm install --ignore-scripts --no-audit --no-fund --prefix "$install_dir" \
	"$test_dir/agentknock-1.2.3.tgz" --loglevel=error

actual=$(AGENTKNOCK_NPM_TEST=preserved \
	"$install_dir/node_modules/.bin/agentknock" first "two words")
expected=$(printf '%s\n' preserved first "two words")
[ "$actual" = "$expected" ] || {
	printf 'npm launcher did not preserve its environment and arguments\n' >&2
	exit 1
}

printf 'npm package tests passed\n'
