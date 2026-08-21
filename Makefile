.PHONY: check fix fmt-check fmt-fix clippy-check clippy-fix test release-build docs

check: fmt-check clippy-check test release-build docs

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

release-build:
	cargo build --locked --release --all-features

docs:
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
