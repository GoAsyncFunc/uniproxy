fmt:
	@gofumpt -l -w .
	@gofmt -s -w .
	@gci write -s standard -s "prefix(github.com/GoAsyncFunc/)" -s "default" .

fmt_install:
	go install -v mvdan.cc/gofumpt@v0.9.2
	go install -v github.com/daixiang0/gci@v0.13.7

lint:
	GOOS=linux golangci-lint run
	GOOS=windows golangci-lint run
	GOOS=darwin golangci-lint run
	GOOS=freebsd golangci-lint run

lint_install:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2

test:
	go test ./...
