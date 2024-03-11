proto: 
	@cargo build --release --manifest-path=showcase/src/sesman/protoc_rust/Cargo.toml
	@rsync -a showcase/src/sesman/protoc_rust/target/release/protoc_rust showcase/src/sesman/protoc_rust.run
	@(cd showcase/src/sesman && ./protoc_rust.run -p ./ -r ./protogen)

demo_keygen: build
	@tmux new-session -s eddsa   \
		-n Li  -d ";" new-window \
		-n Na  -d ";" new-window \
		-n K   -d ";" new-window \
		-n Rb  -d ";" new-window \
		-n Cs  -d ";" new-window \
		-n Be  -d ";" new-window \
		-n Mg  -d ";" new-window \
		-n Ca  -d ";" new-window \
		-n Sr  -d ";" new-window \
		-n Ba  -d ";" new-window \
		-n man -d ";"
	@sleep 1
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./demo_sesman_server > log.txt" C-m
	@sleep 5
	@tmux send-keys -t eddsa:Li "cd $(shell pwd)/out && ./demo_keygen -n Li " C-m
	@tmux send-keys -t eddsa:Na "cd $(shell pwd)/out && ./demo_keygen -n Na " C-m
	@tmux send-keys -t eddsa:K  "cd $(shell pwd)/out && ./demo_keygen -n K  " C-m
	@tmux send-keys -t eddsa:Rb "cd $(shell pwd)/out && ./demo_keygen -n Rb " C-m
	@tmux send-keys -t eddsa:Cs "cd $(shell pwd)/out && ./demo_keygen -n Cs " C-m
	@tmux send-keys -t eddsa:Be "cd $(shell pwd)/out && ./demo_keygen -n Be " C-m
	@tmux send-keys -t eddsa:Mg "cd $(shell pwd)/out && ./demo_keygen -n Mg " C-m
	@tmux send-keys -t eddsa:Ca "cd $(shell pwd)/out && ./demo_keygen -n Ca " C-m
	@tmux send-keys -t eddsa:Sr "cd $(shell pwd)/out && ./demo_keygen -n Sr " C-m
	@tmux send-keys -t eddsa:Ba "cd $(shell pwd)/out && ./demo_keygen -n Ba " C-m

demo_sign: build
	@tmux new-session -s eddsa   \
		-n Li  -d ";" new-window \
		-n Na  -d ";" new-window \
		-n K   -d ";" new-window \
		-n Be  -d ";" new-window \
		-n Mg  -d ";" new-window \
		-n Ca  -d ";" new-window \
		-n Ba  -d ";" new-window \
		-n man -d ";"
	@sleep 1
	@tmux send-keys -t eddsa:man "cd $(shell pwd)/out && ./demo_sesman_server" C-m
	@sleep 1
	@tmux send-keys -t eddsa:Li "cd $(shell pwd)/out && ./demo_sign -n Li " C-m
	@tmux send-keys -t eddsa:Na "cd $(shell pwd)/out && ./demo_sign -n Na " C-m
	@tmux send-keys -t eddsa:K  "cd $(shell pwd)/out && ./demo_sign -n K  " C-m
	@tmux send-keys -t eddsa:Be "cd $(shell pwd)/out && ./demo_sign -n Be " C-m
	@tmux send-keys -t eddsa:Mg "cd $(shell pwd)/out && ./demo_sign -n Mg " C-m
	@tmux send-keys -t eddsa:Ca "cd $(shell pwd)/out && ./demo_sign -n Ca " C-m
	@tmux send-keys -t eddsa:Ba "cd $(shell pwd)/out && ./demo_sign -n Ba " C-m
