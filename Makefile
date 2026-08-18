# OAST Makefile
APP      := oast
PKG      := github.com/oast/oast
BIN      := bin/$(APP)
GOFLAGS  := -trimpath -ldflags "-s -w"

.PHONY: all build run test race vet fmt tidy clean

all: build

build:
	go build $(GOFLAGS) -o $(BIN) ./cmd/oast

run:
	go run ./cmd/oast -config configs/config.yaml

test:
	go test ./...

race:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -s -w .
	goimports -w -local $(PKG) . 2>/dev/null || true

tidy:
	go mod tidy

clean:
	rm -rf bin
