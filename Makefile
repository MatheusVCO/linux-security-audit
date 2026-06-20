.PHONY: build lint clean help

SHELL    := /bin/bash
DIST_DIR := dist
SCRIPTS  := main.sh lib/common.sh checks/network.sh checks/services.sh checks/ssh.sh checks/users.sh

help:
	@echo "Targets:"
	@echo "  build   Gera $(DIST_DIR)/audit.sh (arquivo unico para deploy em servidor)"
	@echo "  lint    Executa shellcheck em todos os scripts"
	@echo "  clean   Remove $(DIST_DIR)/"

build: $(DIST_DIR)/audit.sh

$(DIST_DIR)/audit.sh: main.sh
	@bash scripts/build.sh

lint:
	@shellcheck $(SCRIPTS)

clean:
	rm -rf $(DIST_DIR)
