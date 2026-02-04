GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_DIR := bin
BIN := $(BIN_DIR)/safnari-$(GOOS)-$(GOARCH)$(EXT)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
JSONV2 ?= 1
TAGS :=
GOEXPERIMENT :=

ifeq ($(JSONV2),1)
TAGS = jsonv2
GOEXPERIMENT = jsonv2
endif

.PHONY: build build-all fmt test lint clean

build:
	@mkdir -p $(BIN_DIR)
	cd src && GOOS=$(GOOS) GOARCH=$(GOARCH) GOEXPERIMENT=$(GOEXPERIMENT) go build -tags "$(TAGS)" -o ../$(BIN) ./cmd

build-all:
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		GOOS=$$os GOARCH=$$arch $(MAKE) build; \
	done

test:
	cd src && GOEXPERIMENT=$(GOEXPERIMENT) go test -tags "$(TAGS)" ./...

lint:
	cd src && GOEXPERIMENT=$(GOEXPERIMENT) go vet -tags "$(TAGS)" ./...

fmt:
	cd src && gofmt -w .

clean:
	rm -rf $(BIN_DIR)
