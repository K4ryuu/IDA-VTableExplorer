# Internal Makefile for Docker builds - no Docker check needed

# Platform detection (via env vars in Docker, uname for native)
PLATFORM ?= $(shell uname -s)

# Default values - IDA SDK requires C++17
USE_COMPILER   := g++
COMPILER_FLAGS := -O2 -std=c++17 -Wreturn-type
LINKER_FLAGS   :=

OBJ_DIR        := obj/
CPP_FILES      := $(wildcard ./src/*.cpp)

# Platform-specific settings
ifeq ($(PLATFORM),Linux)
    # Linux - GCC (official)
    USE_COMPILER   := g++
    COMPILER_FLAGS += -Isdk/src/include
    COMPILER_FLAGS += -fPIC
    COMPILER_FLAGS += -D__LINUX__ -D__EA64__
    LINKER_FLAGS   := -shared
    RELEASE_NAME   := vtable64.so

else ifeq ($(PLATFORM),Darwin)
    # macOS - Clang (official)
    ARCH           ?= arm64
    ifeq ($(ARCH),x86_64)
        USE_COMPILER   := o64-clang++
        COMPILER_FLAGS += -Isdk/src/include
        COMPILER_FLAGS += -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -Lsdk/src/lib/x64_mac_clang_64
        RELEASE_NAME   := vtable64-macos-x64.dylib
    else
        USE_COMPILER   := oa64-clang++
        COMPILER_FLAGS += -Isdk/src/include
        COMPILER_FLAGS += -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -Lsdk/src/lib/arm64_mac_clang_64
        RELEASE_NAME   := vtable64-macos-arm64.dylib
    endif
    LINKER_FLAGS   := -dynamiclib -undefined dynamic_lookup -lida

else
    # Windows - MinGW cross-compile
    # WARNING: MinGW has ABI incompatibility with MSVC for C++ virtual functions!
    # Plugins using chooser_t will NOT work correctly.
    # For proper Windows builds, use Visual Studio 2022+ with MSVC.
    USE_COMPILER   := x86_64-w64-mingw32-g++
    COMPILER_FLAGS += -Isdk/src/include
    COMPILER_FLAGS += -D__NT__ -D__EA64__
    COMPILER_FLAGS += -Lsdk/src/lib/x64_win_vc_64
    LINKER_FLAGS   := -static -shared
    LINKER_FLAGS   += -Wl,--kill-at
    LINKER_FLAGS   += -l:ida.lib
    RELEASE_NAME   := vtable64.dll
endif

.PHONY: all clean

all:
	@mkdir -p $(OBJ_DIR)
	@echo "Building for $(PLATFORM) with $(USE_COMPILER)..."
	@count=0; \
	for file in $(CPP_FILES); do \
	  echo "  Compiling: $$file"; \
	  $(USE_COMPILER) $$file -c -o $(OBJ_DIR)$$count.o $(COMPILER_FLAGS); \
	  count=$$((count + 1)); \
	done
	@mkdir -p release
	@echo "  Linking: $(RELEASE_NAME)"
	@$(USE_COMPILER) -o release/$(RELEASE_NAME) $(COMPILER_FLAGS) $(OBJ_DIR)*.o $(LINKER_FLAGS)
	@echo "Done: release/$(RELEASE_NAME)"

clean:
	@rm -rf $(OBJ_DIR) release/
