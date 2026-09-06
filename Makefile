BINARY=secskills
INSTALL_DIR?=$(shell go env GOPATH)/bin

.PHONY: all build test vet install clean doctor mcp-check

all: build

build:            ## Build the single binary (embeds KB + rules)
	go build -o $(BINARY) .

test:             ## Run unit tests
	go test ./...

vet:              ## go vet
	go vet ./...

install: build    ## Install to $(INSTALL_DIR)
	install -m 0755 $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "installed $(BINARY) -> $(INSTALL_DIR)"

doctor: build     ## Build then run the tool doctor
	./$(BINARY) doctor

selftest: build     ## End-to-end pipeline test (local disposable server)
	./$(BINARY) selftest

mcp-check: build  ## Smoke-test the MCP server (initialize + tools/list)
	@printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | ./$(BINARY) mcp

clean:            ## Remove build artifacts
	rm -f $(BINARY)

help:             ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'
