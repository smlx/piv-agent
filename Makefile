.PHONY: build
build: test
	go build ./cmd/piv-agent

.PHONY: test
test: mod-tidy generate
	go test -v ./...

.PHONY: generate
generate: mod-tidy
	go generate ./...

.PHONY: mod-tidy
mod-tidy:
	go mod tidy
