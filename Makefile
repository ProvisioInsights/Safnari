GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)
EXT := $(if $(filter windows,$(GOOS)),.exe,)
BIN_DIR := bin
BIN := $(BIN_DIR)/safnari-$(GOOS)-$(GOARCH)$(EXT)
PGO_PROFILE ?= src/pgo/default.pgo
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
JSONV2 ?= 1
TAGS :=
GOEXPERIMENT :=

ifeq ($(JSONV2),1)
TAGS = jsonv2
GOEXPERIMENT = jsonv2
endif

.PHONY: build build-all build-pgo build-pgo-ultra profile-generate bench-baseline bench-ultra bench-gate bench-compare bench-simd fmt test lint clean

build:
	@mkdir -p $(BIN_DIR)
	cd src && GOOS=$(GOOS) GOARCH=$(GOARCH) GOEXPERIMENT=$(GOEXPERIMENT) go build -tags "$(TAGS)" -o ../$(BIN) ./cmd

build-all:
	@mkdir -p $(BIN_DIR)
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		GOOS=$$os GOARCH=$$arch $(MAKE) build; \
	done

build-pgo:
	@if [ ! -f "$(PGO_PROFILE)" ]; then \
		if [ "$${PGO_REQUIRED:-0}" = "1" ]; then \
			echo "PGO profile missing: $(PGO_PROFILE)"; \
			exit 1; \
		fi; \
		echo "PGO profile not found at $(PGO_PROFILE); skipping build-pgo. Set PGO_REQUIRED=1 to fail instead."; \
	else \
		mkdir -p $(BIN_DIR); \
		profile="$(PGO_PROFILE)"; \
		case "$$profile" in src/*) profile="$${profile#src/}" ;; esac; \
		cd src && GOOS=$(GOOS) GOARCH=$(GOARCH) GOEXPERIMENT=$(GOEXPERIMENT) go build -tags "$(TAGS)" -pgo=$$profile -o ../$(BIN) ./cmd; \
		fi

build-pgo-ultra: profile-generate
	PGO_REQUIRED=1 $(MAKE) build-pgo

test:
	cd src && GOEXPERIMENT=$(GOEXPERIMENT) go test -tags "$(TAGS)" ./...

lint:
	cd src && GOEXPERIMENT=$(GOEXPERIMENT) go vet -tags "$(TAGS)" ./...

fmt:
	cd src && gofmt -w .

profile-generate:
	./scripts/bench/profile-generate.sh $(PGO_PROFILE)

bench-baseline:
	./scripts/bench/baseline.sh

bench-ultra:
	./scripts/bench/baseline.sh

bench-gate:
	./scripts/bench/gate.sh

bench-compare:
	@if [ -z "$${BASELINE:-}" ] || [ -z "$${CANDIDATE:-}" ]; then \
		echo "Usage: make bench-compare BASELINE=<baseline.txt> CANDIDATE=<candidate.txt> [OUT=<report.txt>]"; \
		exit 1; \
	fi
	./scripts/bench/compare.sh "$$BASELINE" "$$CANDIDATE" "$${OUT:-}"

bench-simd:
	./scripts/bench/simd.sh

clean:
	rm -rf $(BIN_DIR)
