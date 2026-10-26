.PHONY: fmt fix nginx nginx-test

fmt:
	cargo +nightly fmt

fix:
	__CARGO_FIX_YOLO=1 cargo +nightly fix

nginx:
	cargo build -p openshield-nginx --features vendored

nginx-test: nginx
	cargo test -p openshield-nginx --features vendored
