VERSION := 0.1.0
LDFLAGS := -ldflags="-X main.Version=$(VERSION) -s -w"
GO      := go

.PHONY: build cross test clean

build:
	$(GO) build $(LDFLAGS) -o bin/mcpaudit.exe .

cross:
	GOOS=linux   GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/mcpaudit-linux-amd64 .
	GOOS=darwin  GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/mcpaudit-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64  $(GO) build $(LDFLAGS) -o dist/mcpaudit-darwin-arm64 .
	GOOS=windows GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/mcpaudit-windows-amd64.exe .

test:
	$(GO) test ./...

clean:
	rm -rf bin/ dist/
