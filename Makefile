EXECUTABLES = demo_sesman_server demo_keygen demo_sign
CARGO_FLAGS = 
TARGET_SUBDIR = debug
ifeq ($(PROFILE),release)
	CARGO_FLAGS += --release
	TARGET_SUBDIR = release
endif

.PHONY: all clean

all: build

build: kill_tmux
	cargo fmt
	cargo build $(CARGO_FLAGS)
	mkdir out || true
	for exe in $(EXECUTABLES); do \
		cp target/$(TARGET_SUBDIR)/$$exe out/$$exe; \
	done

include showcase/deploy_showcase.mk

clean: kill_tmux
	cargo clean
	rm -r out

kill_tmux:
	tmux kill-session -t eddsa || true
