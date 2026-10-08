MODULE   = $(shell env GO111MODULE=on $(GO) list -m)
DATE    ?= $(shell date +%FT%T%z)
PKGS     = $(or $(PKG),$(shell env GO111MODULE=on $(GO) list ./...))
TESTPKGS = $(shell env GO111MODULE=on $(GO) list -f \
			'{{ if or .TestGoFiles .XTestGoFiles }}{{ .ImportPath }}{{ end }}' \
			$(PKGS))
BIN      = $(CURDIR)/bin

GO      = go
TIMEOUT = 15
V = 0
Q = $(if $(filter 1,$V),,@)
M = $(shell printf "\033[34;1m▶\033[0m")

binext=""
ifeq ($(GOOS),windows)
  binext=".exe"
endif

export GO111MODULE=on

.PHONY: all
all: fmt lint vet build

.PHONY: build
build: $(BIN) ; $(info $(M) building executable…) @ ## Build program binary
	$Q CGO_ENABLED=0 $(GO) build \
		-ldflags "-X main.gitVersion=$$(git describe --tags) -X $(MODULE)/cmd.gitVersion=$$(git describe --tags) -X \"main.buildTime=$$(date -u '+%Y-%m-%d %H:%M:%S %Z')\" -X \"$(MODULE)/cmd.buildTime=$$(date -u '+%Y-%m-%d %H:%M:%S %Z')\"" \
		-tags release \
		-o $(BIN)/$(notdir $(basename $(MODULE)))$(binext)
# Tools

$(BIN):
	@mkdir -p $@
$(BIN)/%: | $(BIN) ; $(info $(M) building $(PACKAGE)…)
	$Q env GOBIN=$(BIN) $(if $(TOOLCHAIN),GOTOOLCHAIN=$(TOOLCHAIN)) $(GO) install $(PACKAGE) \
		|| ret=$$?; \
	   exit $$ret

# golang:1 is Go 1.27.2, whose export data is version 5. staticcheck v0.8.1
# (still @latest) and errcheck v1.20.0 only decode through version 4, so they
# must load packages with the toolchain declared in go.mod.
ANALYZER_GO = go1.26.8

GOLINT = $(BIN)/golint
$(BIN)/golint: PACKAGE=golang.org/x/lint/golint@latest

STATICCHECK = $(BIN)/staticcheck
$(BIN)/staticcheck: PACKAGE=honnef.co/go/tools/cmd/staticcheck@v0.8.1
$(BIN)/staticcheck: TOOLCHAIN=$(ANALYZER_GO)

ERRCHECK = $(BIN)/errcheck
$(BIN)/errcheck: PACKAGE=github.com/kisielk/errcheck@v1.20.0
$(BIN)/errcheck: TOOLCHAIN=$(ANALYZER_GO)

VULNCHECK = $(BIN)/govulncheck
$(BIN)/govulncheck: PACKAGE=golang.org/x/vuln/cmd/govulncheck@latest

# Tests

TEST_TARGETS := test-default test-bench test-short test-verbose test-race
.PHONY: $(TEST_TARGETS) check test tests
test-bench:   ARGS=-run=__absolutelynothing__ -bench=. ## Run benchmarks
test-short:   ARGS=-short        ## Run only short tests
test-verbose: ARGS=-v            ## Run tests in verbose mode
test-race:    ARGS=-race         ## Run tests with race detector
$(TEST_TARGETS): NAME=$(MAKECMDGOALS:test-%=%)
$(TEST_TARGETS): test
check test tests: fmt lint vet staticcheck errcheck vulncheck; $(info $(M) running $(NAME:%=% )tests…) @ ## Run tests
	$Q $(GO) test -timeout $(TIMEOUT)s $(ARGS) $(TESTPKGS)
	$Q python3 internal/workflowscripts/sync_malware_formatter_templates.py
	$Q python3 -m unittest discover -s internal/workflowscripts -p 'test_*.py'
	$Q node --test internal/workflowscripts/*.test.js

.PHONY: lint-scripts
lint-scripts: ; $(info $(M) linting dependency-cursor-review scripts…) @ ## Ruff, shfmt, and shellcheck on synced scripts
	$Q REQUIRE_DCR_LINT=1 python3 -m unittest discover -s internal/workflowscripts -p 'test_consumer_lint.py'

.PHONY: fmt
fmt: ; $(info $(M) running gofmt…) @ ## Run gofmt on all source files
	$Q $(GO) fmt $(PKGS)

# Run fmt before any linter so parallel `-jN` doesn't change files while a linter is mid flight.
lint vet staticcheck errcheck vulncheck: fmt

.PHONY: lint
lint: | $(GOLINT) ; $(info $(M) running golint…) @ ## Run golint
	$Q $(GOLINT) -set_exit_status $(PKGS)

.PHONY: vet
vet: ; $(info $(M) running go vet…) @ ## Run go vet on all source files
	$Q $(GO) vet $(PKGS)

.PHONY: staticcheck
staticcheck: | $(STATICCHECK) ; $(info $(M) running staticcheck…) @
	$Q GOTOOLCHAIN=$(ANALYZER_GO) $(STATICCHECK) $(PKGS)

.PHONY: errcheck
errcheck: | $(ERRCHECK) ; $(info $(M) running errcheck…) @
	$Q GOTOOLCHAIN=$(ANALYZER_GO) $(ERRCHECK) $(PKGS)

.PHONY: vulncheck
vulncheck: | $(VULNCHECK) ; $(info $(M) running vulncheck…) @
	$Q $(VULNCHECK) $(PKGS)

# Misc

.PHONY: clean
clean: ; $(info $(M) cleaning…)	@ ## Cleanup everything
	@rm -rf $(BIN)
	@rm -rf test/tests.*

.PHONY: help
help:
	@grep -hE '^[ a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-17s\033[0m %s\n", $$1, $$2}'
