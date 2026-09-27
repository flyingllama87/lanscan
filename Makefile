GIT_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
VERSION ?= $(if $(GIT_VERSION),$(GIT_VERSION),development)
BUILDDIR ?= build
DISTDIR ?= dist
TOOLDIR ?= $(BUILDDIR)/tools
BINDIR ?= /usr/local/bin
GO_INSTALL_DIR ?= /usr/local
GO_VERSION ?=
GOOS ?= $(shell go env GOOS 2>/dev/null || uname -s | tr '[:upper:]' '[:lower:]')
GOARCH ?= $(shell go env GOARCH 2>/dev/null || uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/i[3-6]86/386/' -e 's/armv7l/armv6l/')
FUZZTIME ?= 20s
STATICCHECK_VERSION ?= v0.8.1
GOVULNCHECK_VERSION ?= v1.8.0

BIN_EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_NAME := lanscan$(BIN_EXT)
BINARY := $(BUILDDIR)/$(BIN_NAME)
RELEASE_NAME := lanscan-$(VERSION)-$(GOOS)-$(GOARCH)
RELEASE_PLATFORMS := linux/amd64 linux/arm64 linux/386 windows/amd64 windows/arm64
STATICCHECK := $(TOOLDIR)/staticcheck
GOVULNCHECK := $(TOOLDIR)/govulncheck

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
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "clean" "Remove build and release artifacts"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "deps" "Download Go dependencies"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "install-go" "Download and install latest Go to GO_INSTALL_DIR"
	@printf "$(BOLD)Quality Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "check" "Run vet, lint and test (what CI runs first)"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "test" "Run tests with race detection"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "vet" "Run go vet for Linux and Windows"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "lint" "Run gofmt and staticcheck for Linux and Windows"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "vuln" "Run govulncheck"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "fuzz" "Run each fuzz target for FUZZTIME (current: $(FUZZTIME))"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "bench" "Run benchmarks"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "lab" "Run the namespace lab end to end (Linux; needs unprivileged userns)"
	@printf "$(BOLD)Packaging & Release Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n" "release" "Create $(DISTDIR)/$(RELEASE_NAME).tar.gz"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "release-all" "Build release tarballs for all platforms plus SHA256SUMS"
	@printf "$(BOLD)Help Targets:$(RESET)\n"
	@printf "  $(CYAN)%-16s$(RESET) %s\n\n" "help" "Display this list of options (default)"
	@printf "$(BOLD)Configurable Variables$(RESET) (e.g. make install BINDIR=~/.local/bin):\n"
	@printf "  %-16s %s\n" "BINDIR" "Installation directory (current: $(BINDIR))"
	@printf "  %-16s %s\n" "BUILDDIR" "Build output directory (current: $(BUILDDIR))"
	@printf "  %-16s %s\n" "DISTDIR" "Release output directory (current: $(DISTDIR))"
	@printf "  %-16s %s\n" "VERSION" "Version string (current: $(VERSION); from git describe)"
	@printf "  %-16s %s\n" "GOOS" "Target operating system (current: $(GOOS))"
	@printf "  %-16s %s\n" "GOARCH" "Target architecture (current: $(GOARCH))"
	@printf "  %-16s %s\n" "GO_INSTALL_DIR" "Go installation directory (current: $(GO_INSTALL_DIR))"
	@printf "  %-16s %s\n\n" "GO_VERSION" "Specific Go version to install (default: latest)"

.PHONY: build
build: $(BINARY)

.PHONY: clean
clean:
	rm -rf $(BUILDDIR) $(DISTDIR)

.PHONY: deps
deps:
	go mod download

# Always rebuild: the Go build cache makes this cheap and tracks sources itself.
.PHONY: $(BINARY)
$(BINARY):
	@mkdir -p $(BUILDDIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $(BINARY) ./cmd/lanscan

.PHONY: release
release:
	@mkdir -p $(DISTDIR)/$(RELEASE_NAME)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags '-s -w -X main.version=$(VERSION)' -o $(DISTDIR)/$(RELEASE_NAME)/$(BIN_NAME) ./cmd/lanscan
	cp README.md $(DISTDIR)/$(RELEASE_NAME)/
	tar -zcf $(DISTDIR)/$(RELEASE_NAME).tar.gz -C $(DISTDIR) $(RELEASE_NAME)
	rm -rf $(DISTDIR)/$(RELEASE_NAME)

.PHONY: release-all
release-all:
	rm -rf $(DISTDIR)
	@set -e; for p in $(RELEASE_PLATFORMS); do \
		$(MAKE) --no-print-directory release GOOS=$${p%/*} GOARCH=$${p#*/}; \
	done
	cd $(DISTDIR) && sha256sum lanscan-*.tar.gz > SHA256SUMS

.PHONY: check
check: vet lint test

.PHONY: test
test:
	go test -race ./...

.PHONY: vet
vet:
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...

$(STATICCHECK):
	GOOS= GOARCH= GOBIN=$(abspath $(TOOLDIR)) go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

$(GOVULNCHECK):
	GOOS= GOARCH= GOBIN=$(abspath $(TOOLDIR)) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

.PHONY: lint
lint: $(STATICCHECK)
	@unformatted=$$(gofmt -l .); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	GOOS=linux $(STATICCHECK) ./...
	GOOS=windows $(STATICCHECK) ./...

.PHONY: vuln
vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

.PHONY: fuzz
fuzz:
	go test -run XXX -fuzz FuzzReplay -fuzztime $(FUZZTIME) ./internal/journal
	go test -run XXX -fuzz FuzzImports -fuzztime $(FUZZTIME) ./internal/importer
	go test -run XXX -fuzz FuzzCacheParsers -fuzztime $(FUZZTIME) ./internal/platform
	go test -run XXX -fuzz FuzzICMPQuote -fuzztime $(FUZZTIME) ./internal/probe
	go test -run XXX -fuzz FuzzErrorQueue -fuzztime $(FUZZTIME) ./internal/probe

.PHONY: bench
bench:
	go test -run XXX -bench . -benchmem ./...

.PHONY: lab
lab:
	./scripts/netns-lab.sh

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
