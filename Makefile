VERSION ?= 0.1.0
BUILDDIR ?= build
BINDIR ?= /usr/local/bin
GO_INSTALL_DIR ?= /usr/local
GO_VERSION ?=
GOOS ?= $(shell go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')
GOARCH ?= $(shell go env GOARCH 2>/dev/null || uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/i[3-6]86/386/' -e 's/armv7l/armv6l/')
DATE = $(shell date -u +%Y%m%d)

BIN_EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_NAME := lanscan$(BIN_EXT)
BINARY := $(BUILDDIR)/$(BIN_NAME)

# Terminal color support (disabled if NO_COLOR is set)
ifeq ($(NO_COLOR),)
CYAN  := \033[36m
BOLD  := \033[1m
RESET := \033[0m
else
CYAN  :=
BOLD  :=
RESET :=
endif

.DEFAULT_GOAL := help

.PHONY: help
help:
	@printf "\n$(BOLD)Usage:$(RESET) make $(CYAN)<target>$(RESET) [VARIABLE=value]\n\n"
	@printf "$(BOLD)Build & Install Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "build" "Build the lanscan binary ($(BUILDDIR)/lanscan)"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "install" "Install binary to BINDIR (default: $(BINDIR))"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "uninstall" "Remove binary from BINDIR"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "clean" "Remove build artifacts ($(BUILDDIR)/*)"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "deps" "Download Go dependencies"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "install-go" "Download and install latest Go to GO_INSTALL_DIR"
	@printf "$(BOLD)Testing Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "test" "Run tests with race detection"
	@printf "$(BOLD)Packaging & Release Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "release" "Create release tarball for current platform ($(GOOS)/$(GOARCH))"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "release-all" "Build release tarballs for all platforms"
	@printf "$(BOLD)Help Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "help" "Display this list of options (default)"
	@printf "$(BOLD)Configurable Variables$(RESET) (e.g. make install BINDIR=~/.local/bin):\n"
	@printf "  %-16s %s\n" "BINDIR" "Installation directory (current: $(BINDIR))"
	@printf "  %-16s %s\n" "BUILDDIR" "Build output directory (current: $(BUILDDIR))"
	@printf "  %-16s %s\n" "VERSION" "Version string (current: $(VERSION))"
	@printf "  %-16s %s\n" "GOOS" "Target operating system (current: $(GOOS))"
	@printf "  %-16s %s\n" "GOARCH" "Target architecture (current: $(GOARCH))"
	@printf "  %-16s %s\n" "GO_INSTALL_DIR" "Go installation directory (current: $(GO_INSTALL_DIR))"
	@printf "  %-16s %s\n\n" "GO_VERSION" "Specific Go version to install (default: latest)"

.PHONY: build
build: $(BINARY)

.PHONY: clean
clean:
	rm -f $(BUILDDIR)/*

.PHONY: deps
deps:
	go mod download

$(BINARY): deps
	@mkdir -p $(BUILDDIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags '-extldflags "-static" -X main.version=$(VERSION) -X lanscan/internal/app.Version=$(VERSION)' -o $(BINARY) ./cmd/lanscan

.PHONY: release
release:
	$(MAKE) clean
	$(MAKE) build
	tar -zcf lanscan-$(GOOS)-$(GOARCH)-v$(VERSION).tar.gz -C $(BUILDDIR) .

.PHONY: release-all
release-all:
	$(MAKE) release GOOS=linux GOARCH=amd64
	$(MAKE) release GOOS=linux GOARCH=arm64
	$(MAKE) release GOOS=linux GOARCH=386
	$(MAKE) release GOOS=windows GOARCH=amd64
	$(MAKE) release GOOS=windows GOARCH=arm64

.PHONY: test
test:
	go test -race ./...

.PHONY: install
install: build
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f $(BINARY) $(DESTDIR)$(BINDIR)/

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(BINDIR)/lanscan $(DESTDIR)$(BINDIR)/lanscan.exe

.PHONY: install-go installgo go
install-go:
	@set -e; \
	HOST_OS=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	HOST_ARCH=$$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/i[3-6]86/386/' -e 's/armv7l/armv6l/'); \
	TARGET_OS=$${GOOS:-$$HOST_OS}; \
	TARGET_ARCH=$${GOARCH:-$$HOST_ARCH}; \
	if [ -n "$(GO_VERSION)" ]; then \
		VER=$$(echo "$(GO_VERSION)" | sed -E 's/^go//; s/^/go/'); \
	else \
		printf "Checking latest Go version... "; \
		VER=$$(curl -fsSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -n 1); \
		if [ -z "$$VER" ]; then \
			VER=$$(curl -fsSL "https://go.dev/dl/?mode=json" 2>/dev/null | sed -n 's/.*"version": "\(go[0-9.]*\)".*/\1/p' | head -n 1); \
		fi; \
		if [ -z "$$VER" ]; then \
			printf "\nError: Failed to determine latest Go version from go.dev\n" >&2; \
			exit 1; \
		fi; \
		printf "$$VER\n"; \
	fi; \
	TARBALL="$${VER}.$${TARGET_OS}-$${TARGET_ARCH}.tar.gz"; \
	URL="https://go.dev/dl/$${TARBALL}"; \
	SUDO=""; \
	TEST_DIR="$(DESTDIR)$(GO_INSTALL_DIR)"; \
	while [ ! -d "$$TEST_DIR" ] && [ "$$TEST_DIR" != "/" ] && [ "$$TEST_DIR" != "." ]; do \
		TEST_DIR=$$(dirname "$$TEST_DIR"); \
	done; \
	if [ ! -w "$$TEST_DIR" ] && [ "$$(id -u)" -ne 0 ]; then \
		if command -v sudo >/dev/null 2>&1; then \
			SUDO="sudo"; \
		else \
			echo "Error: Directory $(DESTDIR)$(GO_INSTALL_DIR) is not writable and sudo is not available." >&2; \
			echo "Run as root or specify GO_INSTALL_DIR (e.g. make install-go GO_INSTALL_DIR=\$$HOME/.local)" >&2; \
			exit 1; \
		fi; \
	fi; \
	TMP_TAR=$$(mktemp /tmp/go-dist.XXXXXX.tar.gz); \
	printf "Downloading %s...\n" "$$URL"; \
	if command -v curl >/dev/null 2>&1; then \
		curl -fL "$$URL" -o "$$TMP_TAR"; \
	elif command -v wget >/dev/null 2>&1; then \
		wget -q --show-progress "$$URL" -O "$$TMP_TAR"; \
	else \
		echo "Error: curl or wget is required" >&2; \
		rm -f "$$TMP_TAR"; \
		exit 1; \
	fi; \
	if [ ! -s "$$TMP_TAR" ]; then \
		echo "Error: Downloaded file is empty or missing" >&2; \
		rm -f "$$TMP_TAR"; \
		exit 1; \
	fi; \
	printf "Extracting to %s...\n" "$(DESTDIR)$(GO_INSTALL_DIR)/go"; \
	$$SUDO mkdir -p "$(DESTDIR)$(GO_INSTALL_DIR)"; \
	$$SUDO rm -rf "$(DESTDIR)$(GO_INSTALL_DIR)/go"; \
	$$SUDO tar -C "$(DESTDIR)$(GO_INSTALL_DIR)" -xzf "$$TMP_TAR"; \
	rm -f "$$TMP_TAR"; \
	BIN_TEST_DIR="$(DESTDIR)$(BINDIR)"; \
	while [ ! -d "$$BIN_TEST_DIR" ] && [ "$$BIN_TEST_DIR" != "/" ] && [ "$$BIN_TEST_DIR" != "." ]; do \
		BIN_TEST_DIR=$$(dirname "$$BIN_TEST_DIR"); \
	done; \
	BIN_SUDO=""; \
	if [ ! -w "$$BIN_TEST_DIR" ] && [ "$$(id -u)" -ne 0 ]; then \
		if command -v sudo >/dev/null 2>&1; then \
			BIN_SUDO="sudo"; \
		fi; \
	fi; \
	$$BIN_SUDO mkdir -p "$(DESTDIR)$(BINDIR)" 2>/dev/null || true; \
	if [ -d "$(DESTDIR)$(BINDIR)" ]; then \
		$$BIN_SUDO ln -sf "$(GO_INSTALL_DIR)/go/bin/go" "$(DESTDIR)$(BINDIR)/go" 2>/dev/null || true; \
		$$BIN_SUDO ln -sf "$(GO_INSTALL_DIR)/go/bin/gofmt" "$(DESTDIR)$(BINDIR)/gofmt" 2>/dev/null || true; \
	fi; \
	printf "\nGo %s installed successfully to %s\n" "$$VER" "$(DESTDIR)$(GO_INSTALL_DIR)/go"; \
	if [ -x "$(DESTDIR)$(GO_INSTALL_DIR)/go/bin/go" ]; then \
		"$(DESTDIR)$(GO_INSTALL_DIR)/go/bin/go" version; \
	fi; \
	printf "\nNote: Ensure %s is in your PATH\n" "$(BINDIR) or $(GO_INSTALL_DIR)/go/bin"

installgo: install-go
go: install-go
