.PHONY: fmt lint format

 
fmt:
	gofmt -s -w .

 
lint:
	golangci-lint run

 
format:
	goimports -w -local github.com/zcyberseclab/zasset ./...

 
pre-commit: fmt lint format 