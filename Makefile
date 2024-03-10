EXECUTABLES = sesman_server keygen sign
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
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./sesman_server" C-m
	@sleep 1
	@tmux send-keys -t eddsa:p1  "cd $(shell pwd)/out && ./keygen -t 3 -m 1 2 3 4 5 -i 1" C-m
	@tmux send-keys -t eddsa:p2  "cd $(shell pwd)/out && ./keygen -t 3 -m 1 2 3 4 5 -i 2" C-m
	@tmux send-keys -t eddsa:p3  "cd $(shell pwd)/out && ./keygen -t 3 -m 1 2 3 4 5 -i 3" C-m
	@tmux send-keys -t eddsa:p4  "cd $(shell pwd)/out && ./keygen -t 3 -m 1 2 3 4 5 -i 4" C-m
	@tmux send-keys -t eddsa:p5  "cd $(shell pwd)/out && ./keygen -t 3 -m 1 2 3 4 5 -i 5" C-m

demo_sign: build
	@tmux new-session -s eddsa \
		-n p1  -d ";" new-window \
		-n p3  -d ";" new-window \
		-n p5  -d ";" new-window \
		-n man -d ";"
	@sleep 1
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./sesman_server" C-m
	@sleep 1
	@tmux send-keys -t eddsa:p1  "cd $(shell pwd)/out && ./sign -s 1 3 5 -i 1" C-m
	@tmux send-keys -t eddsa:p3  "cd $(shell pwd)/out && ./sign -s 1 3 5 -i 3" C-m
	@tmux send-keys -t eddsa:p5  "cd $(shell pwd)/out && ./sign -s 1 3 5 -i 5" C-m

clean: kill_tmux
	cargo clean
	rm -r out

kill_tmux:
	tmux kill-session -t eddsa || true