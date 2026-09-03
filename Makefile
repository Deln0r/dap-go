# dap-go development makefile.
#
# Run `make check` before every commit. CI runs the same set; if
# `make check` is green locally, the PR will be green too modulo
# go-version matrix differences.

GO ?= go
GOLANGCI_LINT_VERSION ?= v2.12.2
FUZZTIME ?= 30s
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
	@echo "(the project config targets golangci-lint v2)"
	@exit 1
else
	$(GOLANGCI_LINT) run
endif

# Each target is retried once before the build fails. The Go fuzzing coordinator
# reports "context deadline exceeded" when -fuzztime elapses while a worker is
# mid-iteration; that is a harness artefact rather than a corpus failure, it
# lands on a different target from run to run, and it writes no failing input.
# A real failure is deterministic — the input is written under testdata/fuzz and
# replayed from the corpus — so it survives the retry, as does a genuine hang.
.PHONY: fuzz
fuzz:
	@for t in FuzzReportShare FuzzTaskConfiguration FuzzAggregationJobInitReq; do \
		echo "== $$t ($(FUZZTIME)) =="; \
		if ! $(GO) test -run '^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) ./pkg/dap/wire/; then \
			echo "== $$t did not finish cleanly, retrying once =="; \
			$(GO) test -run '^$$' -fuzz="^$$t$$" -fuzztime=$(FUZZTIME) ./pkg/dap/wire/ || exit 1; \
		fi; \
	done

.PHONY: lint-install
lint-install:
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: clean
clean:
	rm -f coverage.txt coverage.html
	$(GO) clean ./...
