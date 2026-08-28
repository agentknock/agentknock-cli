#!/bin/sh

set -eu

fail() {
	printf 'Agentknock installation failed: %s\n' "$*" >&2
	exit 1
}

need_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

download() {
	curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
		--output "$2" "$1"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1"
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1"
	else
		fail 'required command not found: sha256sum or shasum'
	fi
}

cleanup() {
	if [ -n "${staged_binary:-}" ]; then
		rm -f "$staged_binary" || :
	fi
	if [ -n "${download_dir:-}" ]; then
		rm -rf "$download_dir" || :
	fi
}

main() {
	[ "$#" -eq 0 ] || fail "this installer does not accept arguments"

	for command in chmod curl mkdir mktemp mv rm tar uname; do
		need_command "$command"
	done

	case "${HOME:-}" in
		/*) ;;
		*) fail 'HOME must be set to an absolute path' ;;
	esac

	os=$(uname -s)
	architecture=$(uname -m)
	case "$os/$architecture" in
		Linux/x86_64 | Linux/x86-64 | Linux/amd64)
			target=x86_64-unknown-linux-musl ;;
		Linux/aarch64 | Linux/arm64)
			target=aarch64-unknown-linux-musl ;;
		Darwin/arm64 | Darwin/aarch64)
			target=aarch64-apple-darwin ;;
		Darwin/*) fail "unsupported macOS architecture: $architecture" ;;
		Linux/*) fail "unsupported Linux architecture: $architecture" ;;
		*) fail "unsupported operating system: $os" ;;
	esac

	repository_url=https://github.com/agentknock/agentknock-cli
	latest_release_url=$repository_url/releases/latest
	if ! release_url=$(curl --proto '=https' --tlsv1.2 --fail --silent \
		--show-error --location --output /dev/null \
		--write-out '%{url_effective}' "$latest_release_url"); then
		fail 'could not find the latest Agentknock release'
	fi

	release_prefix=$repository_url/releases/tag/
	case "$release_url" in
		"$release_prefix"*) tag=${release_url#"$release_prefix"} ;;
		*) fail "GitHub returned an unexpected release URL: $release_url" ;;
	esac
	case "$tag" in
		v[0-9]*.[0-9]*.[0-9]*) ;;
		*) fail "GitHub returned an invalid release tag: $tag" ;;
	esac
	case "$tag" in
		*[!A-Za-z0-9._+-]*) fail "GitHub returned an invalid release tag: $tag" ;;
	esac

	archive_name=agentknock-$target.tar.gz
	checksum_name=$archive_name.sha256
	release_base=$repository_url/releases/download/$tag

	download_dir=$(mktemp -d) || fail 'could not create a temporary directory'
	trap cleanup 0
	trap 'exit 1' 1 2 15
	archive_path=$download_dir/$archive_name
	checksum_path=$download_dir/$checksum_name

	printf 'Downloading Agentknock %s for %s.\n' "$tag" "$target"
	download "$release_base/$archive_name" "$archive_path" || \
		fail "could not download $archive_name"
	download "$release_base/$checksum_name" "$checksum_path" || \
		fail "could not download $checksum_name"

	if ! IFS=' ' read -r expected_hash expected_name < "$checksum_path"; then
		fail 'the release checksum file is empty'
	fi
	case "$expected_hash" in
		'' | *[!0-9a-f]*) fail 'the release checksum is invalid' ;;
	esac
	[ "${#expected_hash}" -eq 64 ] || fail 'the release checksum is invalid'
	[ "$expected_name" = "$archive_name" ] || \
		fail 'the release checksum names an unexpected file'

	actual_hash_line=$(sha256 "$archive_path") || \
		fail "could not calculate the checksum of $archive_name"
	actual_hash=${actual_hash_line%% *}
	[ "$actual_hash" = "$expected_hash" ] || \
		fail "the checksum of $archive_name does not match"

	install_dir=$HOME/.local/bin
	install_path=$install_dir/agentknock
	mkdir -p "$install_dir" || fail "could not create $install_dir"
	staged_binary=$(mktemp "$install_dir/.agentknock.XXXXXX") || \
		fail "could not create a temporary file in $install_dir"
	if ! tar -xOzf "$archive_path" agentknock > "$staged_binary"; then
		fail "could not extract agentknock from $archive_name"
	fi
	[ -s "$staged_binary" ] || fail 'the release archive contains an empty binary'
	chmod 0755 "$staged_binary" || fail 'could not make the Agentknock binary executable'
	mv -f "$staged_binary" "$install_path" || fail "could not install $install_path"
	staged_binary=

	printf 'Installed Agentknock %s to %s.\n' "$tag" "$install_path"
	case ":${PATH:-}:" in
		*":$install_dir:"*) ;;
		*) printf 'Add %s to PATH to run agentknock without its full path.\n' "$install_dir" ;;
	esac
}

main "$@"
