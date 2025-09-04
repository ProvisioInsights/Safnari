GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_DIR := bin
BIN := $(BIN_DIR)/safnari-$(GOOS)-$(GOARCH)$(EXT)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: build build-all test lint clean

build:
	@mkdir -p $(BIN_DIR)
	cd src && GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o ../$(BIN) ./cmd

build-all:
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		GOOS=$$os GOARCH=$$arch $(MAKE) build; \
	done

test:
	cd src && go test ./...

lint:
	cd src && go vet ./...

clean:
	rm -rf $(BIN_DIR)
