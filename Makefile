CARGO := cargo
DATA_DIR ?= ./data
DB_URL := sqlite://$(DATA_DIR)/db/snpguard.sqlite?mode=rwc
CLIENT_TARGET := x86_64-unknown-linux-musl

.PHONY: all build build-server build-client build-snpguest db-setup clean repack help

all: build

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

build: build-server build-client build-snpguest ## Build Server, Client and snpguest tool

build-server: ## Build Management Server
	$(CARGO) build --release --bin snpguard-server

build-client: ## Build Guest Client (Static)
	@echo "Ensuring MUSL target..."
	rustup target add $(CLIENT_TARGET) || true
	$(CARGO) build --release --bin snpguard-client --target $(CLIENT_TARGET)

build-snpguest: ## Build snpguest tool (Static)
	@echo "Ensuring MUSL target..."
	rustup target add $(CLIENT_TARGET) || true
	cd snpguest && $(CARGO) build --release --target $(CLIENT_TARGET)

db-setup: ## Initialize SQLite Database
	mkdir -p $(DATA_DIR)/db
	export DATABASE_URL="$(DB_URL)"; \
	$(CARGO) run --release -p migration

run-server: db-setup ## Run the Server locally
	export DATA_DIR="$(DATA_DIR)"; \
	export DATABASE_URL="$(DB_URL)"; \
	$(CARGO) run --release --bin snpguard-server

clean: ## Clean artifacts
	$(CARGO) clean
	rm -f data/*.db*
	rm -rf artifacts/*

repack: build-client ## Embed client into initrd (Usage: make repack INITRD_IN=... INITRD_OUT=...)
	./scripts/repack-initrd.sh $(INITRD_IN) $(INITRD_OUT)
