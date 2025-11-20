# VTableExplorer Makefile - Docker multi-platform build

.PHONY: build build-clean check-docker

check-docker:
	@which docker > /dev/null || (printf "\n[!] Docker is not installed or not in PATH\n\n" && \
	printf "    Install Docker:\n" && \
	printf "    ▪ macOS:   https://docs.docker.com/desktop/install/mac-install/\n" && \
	printf "    ▪ Linux:   https://docs.docker.com/engine/install/\n" && \
	printf "    ▪ Windows: https://docs.docker.com/desktop/install/windows-install/\n\n" && \
	exit 1)
	@docker info > /dev/null 2>&1 || ( \
		printf "\n[!] Docker is not running\n\n"; \
		if [ "$$(uname -s)" = "Darwin" ]; then \
			printf "    Starting Docker Desktop...\n"; \
			open -a Docker && sleep 5 && \
			(docker info > /dev/null 2>&1 && printf "    [✓] Docker started successfully\n\n" || \
			(printf "    [!] Failed to start Docker Desktop\n" && \
			printf "    Please start it manually from Applications\n\n" && exit 1)); \
		else \
			printf "    Linux: sudo systemctl start docker\n"; \
			printf "    Windows: Start Docker Desktop\n\n"; \
			exit 1; \
		fi \
	)

build: check-docker
	@printf "[*] Building all platforms via Docker multi-stage build...\n"
	@docker build -f docker/Dockerfile --target artifacts -t vtable-all-artifacts .
	@printf "[*] Extracting binaries...\n"
	@docker create --name vtable-all-extract vtable-all-artifacts
	@mkdir -p release
	@docker cp vtable-all-extract:/vtable64-linux-x64.so release/
	@docker cp vtable-all-extract:/vtable64-macos-arm64.dylib release/
	@docker cp vtable-all-extract:/vtable64-macos-x64.dylib release/
	@docker rm vtable-all-extract
	@docker rmi vtable-all-artifacts
	@printf "\n[*] ========================================\n"
	@printf "[+] Linux & macOS built successfully!\n"
	@printf "\n"
	@printf "    Linux:      release/vtable64-linux-x64.so\n"
	@printf "    macOS ARM:  release/vtable64-macos-arm64.dylib\n"
	@printf "    macOS x64:  release/vtable64-macos-x64.dylib\n"
	@printf "\n"
	@printf "    Note: For Windows, use ida-win-build with Clang MSVC ABI\n"
	@printf "\n"

build-clean:
	@printf "[*] Cleaning Docker artifacts...\n"
	@docker rm -f vtable-all-extract 2>/dev/null || true
	@docker rmi vtable-all-artifacts 2>/dev/null || true
	@printf "[*] Docker cleanup complete\n"
