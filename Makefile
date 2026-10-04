# sparknet master-node — developer entry points
#
# This role is SPECIFIED, NOT BUILT. There is deliberately no scripts/,
# services/ or systemd/ directory here, so almost every target below inspects or
# documents rather than executes. When plans/MASTER_BUILD_PLAN.md Step 3 lands,
# the signing/overlay targets move here for real.
#
# Standalone: the fabric root holding contracts/ and shared/ is resolved from
# this file's location, overridable with SPARKNET_FABRIC_ROOT.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help
VAULT_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
FABRIC_ROOT ?= $(patsubst %/,%,$(dir $(VAULT_ROOT)))

VENV_PY := $(VAULT_ROOT)/.venv/bin/python
PY := $(if $(wildcard $(VENV_PY)),$(VENV_PY),python3)

.PHONY: help env-init validate status plan test test-all lint spec-check \
        bundle wiki-preflight wiki-status wiki-lint wiki-query clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env-init: ## Write this role's .env + wiki dirs from .env.example (idempotent)
	@$(FABRIC_ROOT)/scripts/sparknet-env-init.sh "$(VAULT_ROOT)"

validate: ## Charter, plan and spec self-checks (no code to run yet)
	@for f in AGENTS.md MEMORY.md MISSION.md plans/MASTER_BUILD_PLAN.md \
	          configs/wireguard/master-peer.template; do \
	  [ -f "$(VAULT_ROOT)/$$f" ] || { echo "missing $$f" >&2; exit 1; }; \
	done
	@echo "  ✓ required role files present"
	@if [ -d "$(VAULT_ROOT)/scripts" ] || [ -d "$(VAULT_ROOT)/services" ]; then \
	  echo "  ✗ scripts/ or services/ exists — this role is documented as unbuilt."; \
	  echo "    Either Step 3 of the build plan has landed (update AGENTS.md and" \
	  echo "    the Step 3 DoD) or the directory is accidental." >&2; \
	  exit 1; \
	else \
	  echo "  ✓ no executable surface, as documented"; \
	fi

status: ## Where the build plan stands
	@grep -m1 '^current:' "$(VAULT_ROOT)/plans/MASTER_BUILD_PLAN.md" \
	  || { echo "MASTER_BUILD_PLAN.md has no 'current:' cursor" >&2; exit 1; }
	@printf '\n  steps done: %s of %s\n' \
	  "$$(grep -c '^- \[x\]' "$(VAULT_ROOT)/plans/MASTER_BUILD_PLAN.md")" \
	  "$$(grep -c '^- \[ \]' "$(VAULT_ROOT)/plans/MASTER_BUILD_PLAN.md")"

# Prints the block for whichever step the `current:` cursor points at.
plan: ## Print the active plan step with its DoD
	@cursor="$$(grep -m1 '^current:' "$(VAULT_ROOT)/plans/MASTER_BUILD_PLAN.md" \
	           | sed 's/.*current:[[:space:]]*//')"; \
	if [ "$$cursor" = "done" ]; then echo "plan is terminal: current: done"; exit 0; fi; \
	awk -v want="$$cursor" \
	  '/^## Step /{ inside = (index($$0, "Step " want) > 0) } \
	   inside { print }' "$(VAULT_ROOT)/plans/MASTER_BUILD_PLAN.md"

spec-check: ## Assert the spec/impl boundary has not rotted
	@$(PY) -m pytest "$(VAULT_ROOT)/tests" -q

test: spec-check ## Alias for spec-check — there is no implementation to test

test-all: spec-check ## Alias for spec-check

lint: ## Ruff over the vendored tests; nothing else to lint in this role
	@if [ -x "$(VENV_PY)" ]; then \
	  "$(VENV_PY)" -m ruff check "$(VAULT_ROOT)/tests" ; \
	elif command -v ruff >/dev/null 2>&1; then \
	  ruff check "$(VAULT_ROOT)/tests" ; \
	else \
	  echo "ruff not installed — skipping (optional)."; \
	fi

bundle: ## Build a standalone master bundle into ../dist
	@$(FABRIC_ROOT)/scripts/sparknet-bundle.sh master

# --- wiki skill suite (vendored in the repo, no global skill farm) -------------

wiki-preflight: ## Prove the vendored wiki skills will resolve THIS role's vault
	@source "$(FABRIC_ROOT)/scripts/sparknet-wiki-env.sh"

wiki-status: ## Preflight, then /wiki-status on this role's vault
	@source "$(FABRIC_ROOT)/scripts/sparknet-wiki-env.sh"
	@echo "Run /wiki-status in opencode to see this role's ingest delta."

wiki-lint: ## Preflight, then /wiki-lint on this role's vault
	@source "$(FABRIC_ROOT)/scripts/sparknet-wiki-env.sh"
	@echo "Run /wiki-lint in opencode to audit this vault."

wiki-query: ## Preflight, then /wiki-query against this role's vault
	@source "$(FABRIC_ROOT)/scripts/sparknet-wiki-env.sh"
	@echo "Run /wiki-query in opencode, e.g. /wiki-query how does revocation work"

clean: ## Remove caches
	@find "$(VAULT_ROOT)" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf "$(VAULT_ROOT)/.pytest_cache" "$(VAULT_ROOT)/.ruff_cache"
	@echo "Cleaned caches (left .venv, .state and .cache alone)."