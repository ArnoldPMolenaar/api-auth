.PHONY: clean critic lint security check tools bootstrap

.DEFAULT_GOAL := bootstrap

# Keep standalone gocritic on the same Go toolchain as this project.
GO_TOOLCHAIN ?= go1.25.9
GOCRITIC_VERSION ?= v0.14.0
GOLANGCI_LINT_VERSION ?= v1.64.8
GOVULNCHECK_VERSION ?= v1.1.4

clean:
	rm -rf ./build

critic:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) gocritic check -enableAll ./...

lint:
	golangci-lint run ./...

security:
	govulncheck ./...

check: lint critic

tools:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/go-critic/go-critic/cmd/gocritic@$(GOCRITIC_VERSION)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

bootstrap: tools
	GOTOOLCHAIN=$(GO_TOOLCHAIN) go mod tidy

