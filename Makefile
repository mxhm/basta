PREFIX      ?= $(HOME)/.local
BINDIR      ?= $(PREFIX)/bin
SHAREDIR    ?= $(PREFIX)/share/basta

CARGO       ?= cargo
TARGET      ?= x86_64-unknown-linux-musl
RUST_BIN    := target/$(TARGET)/release/basta

BASH_BINS   := basta-host-setup basta-verify
SHARE       := share/apparmor.bwrap share/apparmor.basta

.PHONY: all build install uninstall test lint clean help

all: help

help:
	@echo "basta — rootless bubblewrap sandbox"
	@echo ""
	@echo "  make build        cargo build --release — run as your user"
	@echo "  make install      install built artifacts to $(PREFIX) (no sudo for ~/.local)"
	@echo "  make uninstall    remove basta + run basta-host-setup --uninstall"
	@echo "  make test         cargo test"
	@echo "  make lint         cargo clippy + shellcheck"

build:
	$(CARGO) build --release --target $(TARGET)
	@ls -la $(RUST_BIN)

# install does not build: `make build` runs as your user (needs cargo);
# `make install` only copies the built artifacts. Default PREFIX is
# ~/.local (no sudo). Use PREFIX=/usr/local sudo make install for a
# system-wide install on shared boxes.
install:
	@test -x "$(RUST_BIN)" || { echo "$(RUST_BIN) missing — run 'make build' first (as your user, not root)"; exit 1; }
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SHAREDIR)
	install -m 0755 $(RUST_BIN) $(DESTDIR)$(BINDIR)/basta
	install -m 0755 $(BASH_BINS) $(DESTDIR)$(BINDIR)/
	install -m 0644 $(SHARE) $(DESTDIR)$(SHAREDIR)/
	@echo ""
	@echo "Installed basta to $(BINDIR). Next: basta-host-setup (one-time host config; prompts for sudo)."

# uninstall: hands the host-side teardown (apparmor + sysctl drop-in) to
# basta-host-setup --uninstall (which self-elevates), then removes the
# user-prefix files. Idempotent — the `|| true` covers
# a re-run where the script is already gone.
uninstall:
	"$(CURDIR)/basta-host-setup" --uninstall || true
	rm -f $(DESTDIR)$(BINDIR)/basta
	rm -f $(addprefix $(DESTDIR)$(BINDIR)/,$(BASH_BINS))
	rm -rf $(DESTDIR)$(SHAREDIR)
	@echo ""
	@echo "basta uninstalled."

test:
	$(CARGO) test --target $(TARGET)

lint:
	$(CARGO) clippy --target $(TARGET) -- -D warnings
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck --severity=warning $(BASH_BINS); else echo "shellcheck not installed"; fi

clean:
	$(CARGO) clean
