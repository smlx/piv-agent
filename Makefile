test: mod-tidy generate
	go test ./...

mod-tidy:
	go mod tidy

generate:
	go generate ./...
