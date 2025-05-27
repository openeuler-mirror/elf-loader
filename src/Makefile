# Build options (override on command line):
# make SMALL=1 DEBUG=1          # Auto-detects architecture
# make ARCH=i386 SMALL=1        # Cross-compile for i386
# make ARCH=aarch64 CROSS=aarch64-linux-gnu-

# Configuration ----------------------------------------------------------------

# Default architecture (auto-detected if not specified)
ARCH ?= $(shell uname -m | sed 's/i[3-6]86/i686/')

# Toolchain prefix for cross-compilation
CROSS ?=

STATIC := 1

# Supported architectures
ARCHS32 := i686
ARCHS64 := x86_64 aarch64 riscv64 loongarch64
ARCHS := $(ARCHS32) $(ARCHS64)

# Target executable
TARGET := loader

# Validate architecture --------------------------------------------------------

ifeq "$(filter $(ARCH),$(ARCHS))" ""
  $(error ARCH='$(ARCH)' is not supported. Choose from: $(ARCHS))
endif

# Toolchain configuration ------------------------------------------------------

CC := $(CROSS)gcc
LD := $(CROSS)ld
AS := $(CROSS)as
OBJCOPY := $(CROSS)objcopy

# Cross-compiler prefixes and package names for each architecture
CROSS_i686 := i686-linux-gnu-
CROSS_x86_64 := x86_64-linux-gnu-
CROSS_aarch64 := aarch64-linux-gnu-
CROSS_riscv64 := riscv64-linux-gnu-
CROSS_loongarch64 := loongarch64-linux-gnu-

PKG_i686 := gcc-i686-linux-gnu libc6-dev-i386-cross
PKG_x86_64 := gcc-x86-64-linux-gnu libc6-dev
PKG_aarch64 := gcc-aarch64-linux-gnu libc6-dev-arm64-cross
PKG_riscv64 := gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
PKG_loongarch64 := gcc-loongarch64-linux-gnu libc6-dev-loong64-cross

# Base flags ------------------------------------------------------------------

COMMON_FLAGS := -pipe -Wall -Wextra -fno-ident -fno-stack-protector -U_FORTIFY_SOURCE
CFLAGS += $(COMMON_FLAGS) -fPIC
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib
LDFLAGS += -e z_start -pie -Wl,-Bsymbolic,--no-undefined,--build-id=none,-Ttext=0x300000
ASFLAGS += $(COMMON_FLAGS) -Wa,--noexecstack

# Add sysroot and include paths for cross-compilation
ifneq "$(CROSS)" ""
  SYSROOT := $(shell $(CC) -print-sysroot)
  CFLAGS += --sysroot=$(SYSROOT)
  CFLAGS += -isystem $(SYSROOT)/usr/include
  CFLAGS += -isystem $(SYSROOT)/usr/include/$(shell $(CC) -dumpmachine)
  LDFLAGS += --sysroot=$(SYSROOT)
  ASFLAGS += --sysroot=$(SYSROOT)
endif

# Architecture-specific flags -------------------------------------------------

ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
  CFLAGS += -m32 -DELFCLASS=ELFCLASS32
  ASFLAGS += -m32
  LDFLAGS += -m32
else
  CFLAGS += -DELFCLASS=ELFCLASS64
  ifeq "$(ARCH)" "riscv64"
    CFLAGS += -march=rv64gc -mabi=lp64d
    ASFLAGS += -march=rv64gc -mabi=lp64d
  else ifeq "$(ARCH)" "loongarch64"
    CFLAGS += -march=loongarch64 -mabi=lp64d
    ASFLAGS += -march=loongarch64 -mabi=lp64d
  endif
endif

# Build mode flags ------------------------------------------------------------

ifdef DEBUG
  CFLAGS += -O0 -ggdb3
  ASFLAGS += -g
else
  CFLAGS += -fvisibility=hidden -Os
  # Disable unwind info to make program smaller
  CFLAGS += -fno-asynchronous-unwind-tables -fno-unwind-tables
  LDFLAGS += -s
endif

ifeq "$(STATIC)" "1"
  CFLAGS += -static
endif

# Source files ----------------------------------------------------------------

SRC_C := $(wildcard *.c)
SRC_ASM := $(wildcard $(ARCH)/*.S)

# Handle SMALL build option
ifdef SMALL
  SRC_C := $(filter-out z_printf.c z_err.c,$(SRC_C))
  CFLAGS += -DZ_SMALL
endif

OBJS := $(SRC_C:.c=.o) $(SRC_ASM:.S=.o)

# Build rules -----------------------------------------------------------------

.PHONY: all clean install-depends release-all release-i686 release-x86_64 release-aarch64 release-riscv64 release-loongarch64

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) $(ASFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(ARCH)/*.o

# Individual release targets ---------------------------------------------------

release-i686:
	@echo "Building for i686..."
	$(MAKE) clean
	@$(MAKE) ARCH=i686 CROSS=$(CROSS_i686)
	@mkdir -p dist
	@cp $(TARGET) dist/elf-loader-i686
	@(cd dist && sha256sum elf-loader-i686 > elf-loader-i686.sha256)

release-x86_64:
	@echo "Building for x86_64..."
	$(MAKE) clean
	@$(MAKE) ARCH=x86_64 CROSS=$(CROSS_x86_64)
	@mkdir -p dist
	@cp $(TARGET) dist/elf-loader-x86_64
	@(cd dist && sha256sum elf-loader-x86_64 > elf-loader-x86_64.sha256)

release-aarch64:
	@echo "Building for aarch64..."
	$(MAKE) clean
	@$(MAKE) ARCH=aarch64 CROSS=$(CROSS_aarch64)
	@mkdir -p dist
	@cp $(TARGET) dist/elf-loader-aarch64
	@(cd dist && sha256sum elf-loader-aarch64 > elf-loader-aarch64.sha256)

release-riscv64:
	@echo "Building for riscv64..."
	$(MAKE) clean
	@$(MAKE) ARCH=riscv64 CROSS=$(CROSS_riscv64)
	@mkdir -p dist
	@cp $(TARGET) dist/elf-loader-riscv64
	@(cd dist && sha256sum elf-loader-riscv64 > elf-loader-riscv64.sha256)

release-loongarch64:
	@echo "Building for loongarch64..."
	$(MAKE) clean
	@$(MAKE) ARCH=loongarch64 CROSS=$(CROSS_loongarch64)
	@mkdir -p dist
	@cp $(TARGET) dist/elf-loader-loongarch64
	@(cd dist && sha256sum elf-loader-loongarch64 > elf-loader-loongarch64.sha256)

# Deploy target --------------------------------------------------------------

release-all:
	make release-i686
	make release-x86_64
	make release-aarch64
	make release-riscv64
	make release-loongarch64
	@echo "Build complete. Binaries and checksums are in dist/"

# Install dependencies --------------------------------------------------------

install-depends:
	@echo "Installing cross-compiler toolchains..."
	@packages="$(PKG_i686) $(PKG_x86_64) $(PKG_aarch64) $(PKG_riscv64) $(PKG_loongarch64)"; \
	echo "Installing packages: $$packages"; \
	sudo apt-get install -y $$packages
	@echo "Dependencies installed successfully."

# Help target -----------------------------------------------------------------

help:
	@echo "Build options:"
	@echo "  ARCH=[$(ARCHS)]    Target architecture (default: auto-detected)"
	@echo "  CROSS=<prefix>     Cross-compiler prefix"
	@echo "  DEBUG=1            Build with debug symbols"
	@echo "  SMALL=1            Exclude printf and error handling"
	@echo "  STATIC=1           Build statically"
	@echo ""
	@echo "Examples:"
	@echo "  make                     # Auto-detect arch"
	@echo "  make ARCH=i686           # Build 32-bit version"
	@echo "  make ARCH=aarch64 CROSS=aarch64-linux-gnu-  # Cross-compile"
	@echo "  make ARCH=riscv64 CROSS=riscv64-linux-gnu-  # Cross-compile for RISC-V"
	@echo "  make ARCH=loongarch64 CROSS=loongarch64-linux-gnu-  # Cross-compile for LoongArch"
	@echo "  make release-all         # Build for all architectures and create checksums"
	@echo "  make release-i686        # Build for i686 only"
	@echo "  make release-x86_64      # Build for x86_64 only"
	@echo "  make release-aarch64     # Build for aarch64 only"
	@echo "  make release-riscv64     # Build for riscv64 only"
	@echo "  make release-loongarch64 # Build for loongarch64 only"
	@echo "  make install-depends     # Install cross-compiler toolchains"
	@echo "  make SMALL=1 DEBUG=1     # Debug build without printf"
