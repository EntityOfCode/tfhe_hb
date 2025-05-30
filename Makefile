.PHONY: compile

compile:
	rebar3 compile

WAMR_VERSION = 2.2.0
WAMR_DIR = _build/wamr

GENESIS_WASM_BRANCH = tillathehun0/cu-experimental
GENESIS_WASM_REPO = https://github.com/permaweb/ao.git
GENESIS_WASM_SERVER_DIR = _build/genesis-wasm-server

ifdef HB_DEBUG
	WAMR_FLAGS = -DWAMR_ENABLE_LOG=1 -DWAMR_BUILD_DUMP_CALL_STACK=1 -DCMAKE_BUILD_TYPE=Debug
else
	WAMR_FLAGS = -DCMAKE_BUILD_TYPE=Release
endif

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
    WAMR_BUILD_PLATFORM = darwin
    ifeq ($(UNAME_M),arm64)
        WAMR_BUILD_TARGET = AARCH64
    else
        WAMR_BUILD_TARGET = X86_64
    endif
else
    WAMR_BUILD_PLATFORM = linux
    WAMR_BUILD_TARGET = X86_64
endif

wamr: $(WAMR_DIR)/lib/libvmlib.a

debug: debug-clean $(WAMR_DIR)
	HB_DEBUG=1 make $(WAMR_DIR)/lib/libvmlib.a
	CFLAGS="-DHB_DEBUG=1" rebar3 compile

debug-clean:
	rm -rf priv
	rm -rf $(WAMR_DIR)

# Clone the WAMR repository at our target release
$(WAMR_DIR):
	git clone \
		https://github.com/bytecodealliance/wasm-micro-runtime.git \
		$(WAMR_DIR) \
		-b WAMR-$(WAMR_VERSION) \
		--single-branch

$(WAMR_DIR)/lib/libvmlib.a: $(WAMR_DIR)
	sed -i '742a tbl_inst->is_table64 = 1;' ./_build/wamr/core/iwasm/aot/aot_runtime.c; \
	cmake \
		$(WAMR_FLAGS) \
		-S $(WAMR_DIR) \
		-B $(WAMR_DIR)/lib \
		-DWAMR_BUILD_TARGET=$(WAMR_BUILD_TARGET) \
		-DWAMR_BUILD_PLATFORM=$(WAMR_BUILD_PLATFORM) \
		-DWAMR_BUILD_MEMORY64=1 \
		-DWAMR_DISABLE_HW_BOUND_CHECK=1 \
		-DWAMR_BUILD_EXCE_HANDLING=1 \
		-DWAMR_BUILD_SHARED_MEMORY=0 \
		-DWAMR_BUILD_AOT=1 \
		-DWAMR_BUILD_LIBC_WASI=0 \
		-DWAMR_BUILD_FAST_INTERP=0 \
		-DWAMR_BUILD_INTERP=1 \
		-DWAMR_BUILD_JIT=0 \
		-DWAMR_BUILD_FAST_JIT=0 \
        -DWAMR_BUILD_DEBUG_AOT=1 \
        -DWAMR_BUILD_TAIL_CALL=1 \
        -DWAMR_BUILD_AOT_STACK_FRAME=1 \
        -DWAMR_BUILD_MEMORY_PROFILING=1 \
        -DWAMR_BUILD_DUMP_CALL_STACK=1
	make -C $(WAMR_DIR)/lib -j8

# TFHE library configuration
TFHE_VERSION = v1.0.1
TFHE_DIR = _build/tfhe
TFHE_BUILD_DIR = $(TFHE_DIR)/build

tfhe: $(TFHE_BUILD_DIR)/libtfhe/libtfhe-nayuki-portable.a

# Clone the TFHE repository
$(TFHE_DIR):
	git clone \
		https://github.com/tfhe/tfhe.git \
		$(TFHE_DIR) \
		-b $(TFHE_VERSION) \
		--single-branch

# Build the TFHE library with all FFT processors
$(TFHE_BUILD_DIR)/libtfhe/libtfhe-nayuki-portable.a: $(TFHE_DIR)
	mkdir -p $(TFHE_BUILD_DIR)
	cd $(TFHE_BUILD_DIR) && cmake ../src \
		-DCMAKE_BUILD_TYPE=Release \
		-DENABLE_TESTS=OFF \
		-DENABLE_FFTW=OFF \
		-DENABLE_NAYUKI_PORTABLE=ON \
		-DENABLE_NAYUKI_AVX=ON \
		-DENABLE_SPQLIOS_AVX=ON \
		-DENABLE_SPQLIOS_FMA=ON \
		-DCMAKE_CXX_FLAGS="-Wno-error=restrict"
	make -C $(TFHE_BUILD_DIR) -j8

clean:
	rebar3 clean
	rm -rf $(TFHE_DIR)

# Add a new target to print the library path
print-lib-path:
	@echo $(CURDIR)/lib/libvmlib.a

$(GENESIS_WASM_SERVER_DIR):
	mkdir -p $(GENESIS_WASM_SERVER_DIR)
	@echo "Cloning genesis-wasm repository..." && \
        tmp_dir=$$(mktemp -d) && \
        git clone --depth=1 -b $(GENESIS_WASM_BRANCH) $(GENESIS_WASM_REPO) $$tmp_dir && \
        mkdir -p $(GENESIS_WASM_SERVER_DIR) && \
        cp -r $$tmp_dir/servers/cu/* $(GENESIS_WASM_SERVER_DIR) && \
        rm -rf $$tmp_dir && \
        echo "Extracted servers/genesis-wasm to $(GENESIS_WASM_SERVER_DIR)"

# Set up genesis-wasm@1.0 environment
setup-genesis-wasm: $(GENESIS_WASM_SERVER_DIR)
	@cp native/genesis-wasm/launch-monitored.sh $(GENESIS_WASM_SERVER_DIR) && \
	if ! command -v node > /dev/null; then \
		echo "Error: Node.js is not installed. Please install Node.js before continuing."; \
		echo "For Ubuntu/Debian, you can install it with:"; \
		echo "  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && \\"; \
		echo "  apt-get install -y nodejs && \\"; \
		echo "  node -v && npm -v"; \
		exit 1; \
	fi
	@cd $(GENESIS_WASM_SERVER_DIR) && npm install > /dev/null 2>&1 && \
		echo "Installed genesis-wasm@1.0 server."
