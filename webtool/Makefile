# 2ms-web — build & run helpers
# Run these from inside the webtool/ directory: `make run`

BINARY  := 2ms-web
BIN_DIR := bin
PKG     := .

.PHONY: help build run install clean release tidy

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

build: ## Compile the single binary into ./bin
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(BINARY) $(PKG)
	@echo "built $(BIN_DIR)/$(BINARY)"

run: build ## Build then start the server (auto-opens the browser)
	./$(BIN_DIR)/$(BINARY)

install: ## Install 2ms-web into your Go bin (so you can run it from anywhere)
	go install $(PKG)
	@echo "installed: run '2ms-web' from anywhere (ensure \$$(go env GOPATH)/bin is on PATH)"

release: ## Cross-compile binaries for macOS/Linux/Windows into ./bin
	./build.sh

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
