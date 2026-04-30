.PHONY: fmt fmt_install lint lint_install test tools ci

fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write -s standard -s "prefix(github.com/GoAsyncFunc/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@v0.9.2
	go install -v github.com/daixiang0/gci@v0.13.7

lint:
	golangci-lint run

lint_install:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2

test:
	go test ./...

tools: fmt_install lint_install
	go install golang.org/x/vuln/cmd/govulncheck@v1.3.0

ci:
	go test -race -coverprofile=coverage.out ./...
	coverage=$$(go tool cover -func=coverage.out | awk '/^total:/ {sub(/%/, "", $$3); print $$3}'); test -n "$$coverage"; awk -v coverage="$$coverage" 'BEGIN { if (coverage < 80) exit 1 }'
	go vet ./...
	go build ./...
	govulncheck ./...
	golangci-lint run
