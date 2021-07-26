test: mod-tidy generate
	go test -v ./...

mod-tidy:
	go mod tidy

generate:
	go generate ./...
