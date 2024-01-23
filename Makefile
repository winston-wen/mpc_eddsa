EXECUTABLES = mpc_sesman demo_keygen demo_sign
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

demo_keygen: build
	@tmux new-session -s eddsa \
		-n p1  -d ";" new-window \
		-n p2  -d ";" new-window \
		-n p3  -d ";" new-window \
		-n p4  -d ";" new-window \
		-n p5  -d ";" new-window \
		-n man -d ";"
	@sleep 1
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./mpc_sesman" C-m
	@sleep 1
	@tmux send-keys -t eddsa:p1  "cd $(shell pwd)/out && ./demo_keygen -t 2 -n 5 -m 1" C-m
	@tmux send-keys -t eddsa:p2  "cd $(shell pwd)/out && ./demo_keygen -t 2 -n 5 -m 2" C-m
	@tmux send-keys -t eddsa:p3  "cd $(shell pwd)/out && ./demo_keygen -t 2 -n 5 -m 3" C-m
	@tmux send-keys -t eddsa:p4  "cd $(shell pwd)/out && ./demo_keygen -t 2 -n 5 -m 4" C-m
	@tmux send-keys -t eddsa:p5  "cd $(shell pwd)/out && ./demo_keygen -t 2 -n 5 -m 5" C-m

demo_sign: build
	@tmux new-session -s eddsa \
		-n p1  -d ";" new-window \
		-n p3  -d ";" new-window \
		-n p5  -d ";" new-window \
		-n man -d ";"
	@sleep 1
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./mpc_sesman" C-m
	@sleep 1
	@tmux send-keys -t eddsa:p1  "cd $(shell pwd)/out && ./demo_sign -n 3 -s 1 -m 1" C-m
	@tmux send-keys -t eddsa:p3  "cd $(shell pwd)/out && ./demo_sign -n 3 -s 2 -m 3" C-m
	@tmux send-keys -t eddsa:p5  "cd $(shell pwd)/out && ./demo_sign -n 3 -s 3 -m 5" C-m

clean: kill_tmux
	cargo clean
	rm -r out

kill_tmux:
	tmux kill-session -t eddsa || true