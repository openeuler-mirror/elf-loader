# Build options (override on command line):
# make SMALL=1 DEBUG=1          # Auto-detects architecture
# make ARCH=i386 SMALL=1        # Cross-compile for i386
# make ARCH=aarch64 CROSS=aarch64-linux-gnu-

# Configuration ----------------------------------------------------------------

# Default architecture (auto-detected if not specified)
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/i[3-6]86/i386/')

# Toolchain prefix for cross-compilation
CROSS ?=

STATIC := 1

# Supported architectures
ARCHS32 := i386
ARCHS64 := amd64 aarch64
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

# Base flags ------------------------------------------------------------------

COMMON_FLAGS := -pipe -Wall -Wextra -fno-ident -fno-stack-protector -U_FORTIFY_SOURCE
CFLAGS += $(COMMON_FLAGS) -fPIC
LDFLAGS += -nostartfiles -nodefaultlibs -nostdlib
LDFLAGS += -e z_start -pie -Wl,-Bsymbolic,--no-undefined,--build-id=none
ASFLAGS += $(COMMON_FLAGS)

# Architecture-specific flags -------------------------------------------------

ifeq "$(filter $(ARCH),$(ARCHS32))" "$(ARCH)"
  CFLAGS += -m32 -DELFCLASS=ELFCLASS32
  ASFLAGS += -m32
  LDFLAGS += -m32
else
  CFLAGS += -DELFCLASS=ELFCLASS64
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

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.S
	$(CC) $(CFLAGS) $(ASFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(ARCH)/*.o

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
	@echo "  make ARCH=i386           # Build 32-bit version"
	@echo "  make ARCH=aarch64 CROSS=aarch64-linux-gnu-  # Cross-compile"
	@echo "  make SMALL=1 DEBUG=1     # Debug build without printf"
