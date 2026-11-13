BINARY=secskills
PKG=./cmd/secskills
VERSION?=$(patsubst v%,%,$(shell git describe --tags --always --dirty 2>/dev/null || echo dev))
LDFLAGS=-s -w -X github.com/gleicon/secskills.Version=$(VERSION)

.PHONY: all build test vet install clean doctor selftest mcp-check dist bundle help

all: build

build:            ## Build the single binary (embeds KB + rules)
	go build -o $(BINARY) $(PKG)

test:             ## Run unit tests
	go test ./...

vet:              ## go vet
	go vet ./...

install:          ## go install into $(go env GOBIN) or $(go env GOPATH)/bin
	go install $(PKG)

doctor: build     ## Build then run the tool doctor
	./$(BINARY) doctor

selftest: build     ## End-to-end pipeline test (local disposable server)
	./$(BINARY) selftest

mcp-check: build  ## Smoke-test the MCP server (initialize + tools/list)
	@printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | ./$(BINARY) mcp

dist:             ## Cross-compile static binaries (no CGO, no LLM) + SHA256SUMS into dist/
	@rm -rf dist && mkdir -p dist
	@for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
		os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/$(BINARY)-$$os-$$arch$$ext $(PKG) || exit 1; \
	done
	@cd dist && (command -v sha256sum >/dev/null && sha256sum $(BINARY)-* || shasum -a 256 $(BINARY)-*) > SHA256SUMS
	@echo "built -> dist/"; ls -la dist/

bundle: dist      ## Package a VM capture kit (binary + scripts + feed cache) into dist/secskills-kit.tar.gz
	@tmp=$$(mktemp -d); kit=$$tmp/secskills-kit; mkdir -p $$kit; \
	cp dist/$(BINARY)-linux-amd64 $$kit/$(BINARY); chmod +x $$kit/$(BINARY); \
	cp deploy/setup.sh deploy/capture.sh deploy/process.sh $$kit/; chmod +x $$kit/*.sh; \
	cp deploy/README.md $$kit/ 2>/dev/null || true; \
	if [ -d "$$HOME/.secskills/feed" ]; then mkdir -p $$kit/feed; cp -R "$$HOME/.secskills/feed/." $$kit/feed/; echo "included feed cache"; else echo "no local feed cache — run 'secskills feed kev' first to ship one"; fi; \
	tar -C $$tmp -czf dist/secskills-kit.tar.gz secskills-kit; rm -rf $$tmp; \
	echo "packaged -> dist/secskills-kit.tar.gz"

clean:            ## Remove build artifacts
	rm -f $(BINARY)
	rm -rf dist

help:             ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'
