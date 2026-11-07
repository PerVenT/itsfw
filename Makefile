# ==============================================================================
# Makefile for it's.fw
# Interactive Windows Filtering Platform & Zero-Trust Firewall TUI
# ==============================================================================

SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Version dynamically extracted from git tag, or fallback to short commit hash
GIT_TAG    := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION    ?= $(if $(GIT_TAG),$(GIT_TAG),$(if $(shell git describe --tags 2>/dev/null),$(shell git describe --tags),dev-$(GIT_COMMIT)))

# Container engine detection (Podman preferred, fallback to Docker)
DOCKER     ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null || echo podman)
IMAGE_NAME ?= itsfw-builder
IMAGE_TAG  ?= latest

# Buildx detection
BUILDX_CMD := $(shell if $(DOCKER) buildx version >/dev/null 2>&1; then echo "$(DOCKER) buildx build"; else echo "$(DOCKER) build"; fi)

# Container runner wrapper with named cargo cache volumes
RUN_IN_CONTAINER = $(DOCKER) run --rm \
	-v cargo-cache:/usr/local/cargo/registry:Z \
	-v cargo-git:/usr/local/cargo/git:Z \
	-v "$$(pwd):/workspace:Z" \
	$(IMAGE_NAME):$(IMAGE_TAG)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

.PHONY: help
help: ## Show this help message
	@echo "Usage: make [target] [VERSION=vX.Y.Z]"
	@echo ""
	@echo "Current Version: $(VERSION)"
	@echo "Container Engine: $(DOCKER)"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: image
image: ## Build cross-compilation builder container image
	@echo "==> Building container image '$(IMAGE_NAME):$(IMAGE_TAG)' via $(BUILDX_CMD)..."
	$(BUILDX_CMD) -t $(IMAGE_NAME):$(IMAGE_TAG) -f Dockerfile .

.PHONY: cargo
cargo: ## Run arbitrary cargo command inside builder container (e.g. make cargo ARGS="check")
	@$(RUN_IN_CONTAINER) cargo $(ARGS)

.PHONY: test
test: ## Run unit tests inside builder container (--no-run for Windows binary)
	@echo "==> Checking test compilation..."
	$(RUN_IN_CONTAINER) cargo test --target x86_64-pc-windows-gnu --no-run $(ARGS)

.PHONY: check
check: ## Run clippy linter inside builder container
	@echo "==> Checking code and lints..."
	$(RUN_IN_CONTAINER) cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings

.PHONY: fmt
fmt: ## Format Rust codebase using rustfmt
	@echo "==> Formatting code..."
	$(RUN_IN_CONTAINER) cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check code formatting without modifying
	@echo "==> Checking formatting..."
	$(RUN_IN_CONTAINER) cargo fmt --all -- --check

.PHONY: build-windows
build-windows: ## Cross-compile release binary for Windows (x86_64-pc-windows-gnu)
	@echo "==> Building Windows release binary (x86_64-pc-windows-gnu)..."
	$(RUN_IN_CONTAINER) cargo build --release --target x86_64-pc-windows-gnu

.PHONY: release
release: build-windows ## Package release binary with SHA256 checksum into dist/
	@echo "==> Packaging release $(VERSION)..."
	@mkdir -p dist
	@rm -rf dist/*
	@$(RUN_IN_CONTAINER) bash -c '\
		set -e; \
		if [ -f target/x86_64-pc-windows-gnu/release/itsfw.exe ]; then \
			cp target/x86_64-pc-windows-gnu/release/itsfw.exe dist/itsfw.exe; \
			(cd dist && zip -9 "itsfw-$(VERSION)-x86_64-pc-windows-gnu.zip" itsfw.exe && rm itsfw.exe); \
			echo "    Created dist/itsfw-$(VERSION)-x86_64-pc-windows-gnu.zip"; \
		else \
			echo "Error: target/x86_64-pc-windows-gnu/release/itsfw.exe not found"; exit 1; \
		fi; \
		echo "==> Generating SHA256 checksums..."; \
		(cd dist && sha256sum itsfw-* > SHA256SUMS.txt); \
		echo "==> Release artifacts ready in dist/:"; \
		ls -la dist/ \
	'

.PHONY: install-windows
install-windows: ## Run Windows installation script (PowerShell)
	@if command -v powershell.exe >/dev/null 2>&1; then \
		powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/install.ps1; \
	elif command -v pwsh >/dev/null 2>&1; then \
		pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/install.ps1; \
	else \
		powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install.ps1; \
	fi

.PHONY: sandbox-test
sandbox-test: build-windows ## Launch isolated E2E test suite inside Windows Sandbox
	@echo "==> Launching Windows Sandbox with it'\''s.fw..."
	@if command -v powershell.exe >/dev/null 2>&1; then \
		powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/launch_sandbox.ps1; \
	elif command -v pwsh >/dev/null 2>&1; then \
		pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/launch_sandbox.ps1; \
	else \
		powershell -NoProfile -ExecutionPolicy Bypass -File scripts/launch_sandbox.ps1; \
	fi

.PHONY: clean
clean: ## Clean build target and dist directories
	@echo "==> Cleaning build artifacts..."
	rm -rf target/ dist/
