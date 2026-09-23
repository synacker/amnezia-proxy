# amnezia-proxy — build, install, deploy, and clean up.
#
# Targets:
#   make build                 build the binary to ./amnezia-proxy
#   make install               install the binary to ~/.local/bin/amnezia-proxy
#   make deploy CONFIG=...     install + generate & start the systemd user unit
#   make clean                 stop/remove the unit and the binary
#
# deploy variables:
#   CONFIG      path to your AmneziaWG config (.vpn or .conf)  [required]
#   SOCKS_PORT  SOCKS5 proxy port             (default 1080)
#   HTTP_PORT   HTTP proxy port               (default 8080)

SHELL := /bin/bash

GO        ?= go
BINARY    := amnezia-proxy
BIN_DIR   ?= $(HOME)/.local/bin
UNIT_DIR  ?= $(HOME)/.config/systemd/user
UNIT_NAME := amnezia-proxy.service

BIN_FILE  := $(BIN_DIR)/$(BINARY)
UNIT_FILE := $(UNIT_DIR)/$(UNIT_NAME)

CONFIG     ?=
SOCKS_PORT ?= 1080
HTTP_PORT  ?= 8080

.PHONY: all build install deploy clean

all: build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '-s -w' -o $(BINARY) .

install: build
	@mkdir -p "$(BIN_DIR)"
	@install -m 0755 "$(BINARY)" "$(BIN_FILE)"
	@echo "installed $(BINARY) -> $(BIN_FILE)"

deploy: install
	@test -n "$(CONFIG)" || { echo "error: CONFIG is required (e.g. make deploy CONFIG=\$$HOME/.vpn/amnezia-proxy.vpn)" >&2; exit 1; }
	@CONFIG_ABS="$(CONFIG)"; \
	CONFIG_ABS="$${CONFIG_ABS/#\~/$(HOME)}"; \
	test -f "$$CONFIG_ABS" || { echo "error: config file not found: $$CONFIG_ABS" >&2; exit 1; }; \
	CONFIG_ABS=$$(readlink -f "$$CONFIG_ABS"); \
	mkdir -p "$(UNIT_DIR)"; \
	sed -e "s|^ExecStart=.*|ExecStart=$(BIN_FILE) -config $$CONFIG_ABS -socks-listen 127.0.0.1:$(SOCKS_PORT) -http-listen 127.0.0.1:$(HTTP_PORT)|" \
	    deploy/amnezia-proxy.service > "$(UNIT_FILE)"
	@systemctl --user daemon-reload
	@systemctl --user enable --now $(UNIT_NAME)
	@-loginctl enable-linger "$$USER"
	@echo "deployed $(UNIT_FILE)"
	@systemctl --user --no-pager --lines=0 status $(UNIT_NAME) || true

clean:
	@-systemctl --user disable --now $(UNIT_NAME)
	@rm -f "$(UNIT_FILE)" "$(BIN_FILE)" "$(BINARY)"
	@-systemctl --user daemon-reload
	@echo "removed $(UNIT_FILE), $(BIN_FILE), and $(BINARY)"
