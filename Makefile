.PHONY: all rust go test run demo demo-python demo-cpp clean

all: rust go

rust:
	cargo build --release --manifest-path rust/Cargo.toml

go: rust
	cd go && go build ./...

test: rust
	cargo test --manifest-path rust/Cargo.toml
	cd go && go test ./...

run: all
	cd go && go run ./cmd/gateway -config ../config/keygate.conf

demo: demo-python demo-cpp

demo-python: all
	python3 examples/python/demo.py

demo-cpp: all
	g++ -std=c++17 examples/cpp/main.cpp -o /tmp/keygate_demo
	/tmp/keygate_demo

clean:
	cargo clean --manifest-path rust/Cargo.toml
	rm -f /tmp/keygate_demo
