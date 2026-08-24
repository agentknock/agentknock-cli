#!/bin/sh

set -eu

repository_root=$(unset CDPATH; cd -- "$(dirname "$0")/.." && pwd)
test_dir=$(mktemp -d)

cleanup() {
	rm -rf "$test_dir"
}
trap cleanup 0
trap 'exit 1' 1 2 15

fail() {
	printf 'installer test failed: %s\n' "$*" >&2
	exit 1
}

assert_contains() {
	grep -F "$2" "$1" >/dev/null || fail "$1 does not contain: $2"
}

fake_bin=$test_dir/bin
fixture_dir=$test_dir/fixture
mkdir -p "$fake_bin" "$fixture_dir"

printf '#!/bin/sh\nprintf "fixture agentknock\\n"\n' > "$fixture_dir/agentknock"
chmod 0755 "$fixture_dir/agentknock"
tar -czf "$test_dir/release.tar.gz" -C "$fixture_dir" agentknock
fixture_hash_line=$(sha256sum "$test_dir/release.tar.gz")
fixture_hash=${fixture_hash_line%% *}

cat > "$fake_bin/uname" <<'EOF'
#!/bin/sh

case "$1" in
	-s) printf '%s\n' "${TEST_OS:-Linux}" ;;
	-m) printf '%s\n' "${TEST_ARCHITECTURE:-x86_64}" ;;
	*) exit 1 ;;
esac
EOF

cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh

set -eu

output=
write_out=
url=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--output | --write-out | --proto)
			option=$1
			value=$2
			shift 2
			case "$option" in
				--output) output=$value ;;
				--write-out) write_out=$value ;;
			esac
			;;
		--tlsv1.2 | --fail | --silent | --show-error | --location)
			shift
			;;
		*)
			url=$1
			shift
			;;
	esac
done

case "$url" in
	https://github.com/agentknock/agentknock-cli/releases/latest)
		: > "$output"
		[ "$write_out" = '%{url_effective}' ] || exit 1
		printf '%s\n' "${TEST_RELEASE_URL:-https://github.com/agentknock/agentknock-cli/releases/tag/v1.2.3}"
		;;
	*/agentknock-*.tar.gz)
		case "$url" in
			*"/agentknock-$TEST_TARGET.tar.gz") ;;
			*) exit 1 ;;
		esac
		cp "$TEST_ARCHIVE" "$output"
		;;
	*/agentknock-*.tar.gz.sha256)
		archive_name=agentknock-$TEST_TARGET.tar.gz
		printf '%s  %s\n' "$TEST_HASH" "$archive_name" > "$output"
		;;
	*)
		exit 1
		;;
esac
EOF

chmod 0755 "$fake_bin/uname" "$fake_bin/curl"

run_installer() {
	home=$1
	output=$2
	HOME=$home PATH=$fake_bin:$PATH sh "$repository_root/install.sh" > "$output" 2>&1
}

run_installer_from_stdin() {
	home=$1
	output=$2
	HOME=$home PATH=$fake_bin:$PATH sh < "$repository_root/install.sh" > "$output" 2>&1
}

export TEST_ARCHIVE="$test_dir/release.tar.gz"
export TEST_HASH="$fixture_hash"

sed '$d' "$repository_root/install.sh" > "$test_dir/truncated-install.sh"
home=$test_dir/truncated-home
HOME=$home PATH=$fake_bin:$PATH sh "$test_dir/truncated-install.sh"
[ ! -e "$home/.local/bin/agentknock" ] || \
	fail 'a truncated installer changed the installation'

home=$test_dir/x86-home
export TEST_ARCHITECTURE=x86_64
export TEST_TARGET=x86_64-unknown-linux-musl
run_installer_from_stdin "$home" "$test_dir/x86-output"
cmp "$fixture_dir/agentknock" "$home/.local/bin/agentknock" || \
	fail 'the x86-64 binary was not installed intact'
[ "$(stat -c %a "$home/.local/bin/agentknock")" = 755 ] || \
	fail 'the installed binary does not have mode 0755'
assert_contains "$test_dir/x86-output" 'Installed Agentknock v1.2.3'

home=$test_dir/arm-home
export TEST_ARCHITECTURE=aarch64
export TEST_TARGET=aarch64-unknown-linux-musl
run_installer "$home" "$test_dir/arm-output"
cmp "$fixture_dir/agentknock" "$home/.local/bin/agentknock" || \
	fail 'the ARM64 binary was not installed intact'

home=$test_dir/checksum-home
mkdir -p "$home/.local/bin"
printf 'existing binary\n' > "$home/.local/bin/agentknock"
export TEST_ARCHITECTURE=x86_64
export TEST_TARGET=x86_64-unknown-linux-musl
export TEST_HASH=0000000000000000000000000000000000000000000000000000000000000000
if run_installer "$home" "$test_dir/checksum-output"; then
	fail 'a bad archive checksum was accepted'
fi
[ "$(cat "$home/.local/bin/agentknock")" = 'existing binary' ] || \
	fail 'a checksum failure changed the existing installation'
assert_contains "$test_dir/checksum-output" 'does not match'

printf 'install.sh tests passed\n'
