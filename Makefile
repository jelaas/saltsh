# saltsh — NaCl-based remote shell
#
# Classic GNU make build for greybeards:
#   make            build the statically linked release binary
#   make install    install it (binary only; the server creates
#                   /etc/saltsh/host_key itself on first start)
#   make test       run the test suite
#   make clean      remove build artifacts
#
# Overridable variables:
#   TARGET    Rust target triple (default: musl static).
#             Use `make TARGET=` to build with cargo's default target.
#   PREFIX    install prefix (default: /usr/local)
#   SBINDIR   where the binary goes (default: $(PREFIX)/sbin)
#   DESTDIR   staging root for packagers

TARGET  ?= x86_64-unknown-linux-musl
CARGO   ?= cargo
PREFIX  ?= /usr/local
SBINDIR ?= $(PREFIX)/sbin
DESTDIR ?=

ifeq ($(TARGET),)
CARGO_TARGET_FLAG =
BIN = target/release/saltsh
else
CARGO_TARGET_FLAG = --target $(TARGET)
BIN = target/$(TARGET)/release/saltsh
endif

SRCS = Cargo.toml Cargo.lock .cargo/config.toml \
       $(shell find src tests -name '*.rs' 2>/dev/null)

.PHONY: all build test install uninstall clean help

all: build

build: $(BIN)

$(BIN): $(SRCS)
	@if [ -n "$(TARGET)" ] && command -v rustup >/dev/null 2>&1 && \
	    ! rustup target list --installed 2>/dev/null | grep -qx '$(TARGET)'; then \
		echo "error: Rust target '$(TARGET)' is not installed."; \
		echo "       fix:  rustup target add $(TARGET)"; \
		exit 1; \
	fi
	$(CARGO) build $(CARGO_TARGET_FLAG) --release
	@echo "built: $(BIN)"

test:
	$(CARGO) test $(CARGO_TARGET_FLAG)

install: build
	install -d $(DESTDIR)$(SBINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(SBINDIR)/saltsh

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/saltsh

clean:
	$(CARGO) clean

help:
	@echo "targets:"
	@echo "  make             build the release binary ($(BIN))"
	@echo "  make test        run the test suite"
	@echo "  make install     install to $(DESTDIR)$(SBINDIR)/saltsh"
	@echo "  make uninstall   remove the installed binary"
	@echo "  make clean       remove build artifacts"
	@echo "variables:"
	@echo "  TARGET   Rust target triple (default: $(TARGET); TARGET= for native)"
	@echo "  PREFIX   install prefix (default: /usr/local)"
	@echo "  SBINDIR  binary directory (default: $(PREFIX)/sbin)"
	@echo "  DESTDIR  staging root for packagers"
