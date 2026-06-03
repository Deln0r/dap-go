# dap-go development makefile.
#
# Run `make check` before every commit. CI runs the same set; if
# `make check` is green locally, the PR will be green too modulo
# go-version matrix differences.

GO ?= go
GOLANGCI_LINT_VERSION ?= v1.64.8
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2> /dev/null)

.PHONY: check
check: fmt-check vet test lint

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt would reformat:"; \
		echo "$$out"; \
		exit 1; \
	fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test -race -coverprofile=coverage.txt -covermode=atomic ./...

.PHONY: lint
lint:
ifndef GOLANGCI_LINT
	@echo "golangci-lint not found on PATH."
	@echo "Install matching CI version with:"
	@echo "  $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)"
	@echo "(brew installs v2 by default; the project config is v1)"
	@exit 1
else
	$(GOLANGCI_LINT) run
endif

.PHONY: lint-install
lint-install:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: clean
clean:
	rm -f coverage.txt coverage.html
	$(GO) clean ./...
