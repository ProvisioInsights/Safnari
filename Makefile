GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_DIR := bin
BIN := $(BIN_DIR)/safnari-$(GOOS)-$(GOARCH)$(EXT)

.PHONY: build test lint clean

build:
	@mkdir -p $(BIN_DIR)
	cd src && GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o ../$(BIN) ./cmd

test:
	cd src && go test ./...

lint:
	cd src && go vet ./...

clean:
	rm -rf $(BIN_DIR)
