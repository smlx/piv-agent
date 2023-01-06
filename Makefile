.PHONY: test
test: mod-tidy generate
	CGO_ENABLED=1 go test -v ./...

.PHONY: generate
generate: mod-tidy
	go generate ./...

.PHONY: mod-tidy
mod-tidy:
	go mod tidy

.PHONY: build
build: test
	CGO_ENABLED=1 go build ./cmd/piv-agent
