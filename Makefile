DIST_DIR := target/dist
DIST_LINK := target/nix-dist
DIST_TARGET := x86_64-unknown-linux-musl

.PHONY: check fix fmt-check fmt-fix clippy-check clippy-fix test installer-check installer-dist release-build docs package-check dependency-check dist dist-check

check: fmt-check clippy-check test installer-check release-build docs

fix: fmt-fix clippy-fix

fmt-fix:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy-check:
	cargo clippy --locked --all-targets --all-features -- -D warnings

clippy-fix:
	cargo clippy --fix --locked --all-targets --all-features --allow-dirty --allow-staged -- -D warnings

test:
	cargo test --locked --all-targets --all-features
	cargo test --locked --doc --all-features

installer-check:
	sh -n install.sh
	sh tests/install.sh

installer-dist: installer-check
	install -d target/installer
	install -m 0755 install.sh target/installer/install.sh
	cd target/installer && sha256sum install.sh > install.sh.sha256

release-build:
	cargo build --locked --release --all-features

docs:
	RUSTDOCFLAGS="-D warnings -D missing_docs" cargo doc --locked --no-deps --all-features

package-check:
	cargo package --locked

dependency-check:
	cargo deny check

dist:
	nix --extra-experimental-features 'nix-command flakes' build \
		--no-update-lock-file --print-build-logs --out-link "$(DIST_LINK)" .#dist
	install -d "$(DIST_DIR)"
	install -m 0644 \
		"$(DIST_LINK)/agentknock-$(DIST_TARGET).tar.gz" \
		"$(DIST_LINK)/agentknock-$(DIST_TARGET).tar.gz.sha256" \
		"$(DIST_DIR)"

dist-check: dist
	./scripts/check-dist "$(DIST_TARGET)" "$(DIST_DIR)"
