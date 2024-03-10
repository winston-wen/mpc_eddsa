.PHONY: all

all: rust

rust:
	@cargo build --release --manifest-path=protoc_rust/Cargo.toml
	@rsync -a protoc_rust/target/release/protoc_rust ./protoc_rust.run
	@./protoc_rust.run -p ./ -r ./protogen

clean:
	@rm -rf protoc_rust.run
