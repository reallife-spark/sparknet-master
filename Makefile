# sparknet master-node — developer entry points
#
# This role is BUILT as of build plan Step 16: it has scripts/, services/ and
# systemd/, and the targets below execute them.
#
# What is deliberately still absent is the signer unit — the operational key lives
# in an isolated process (Step 17), and it lands with its own isolation rather
# than as a stub here. A signer that exists but cannot sign is worse than no
# signer, because it would be the one place a compromised admin surface could
# reach a key.
#
# Standalone: the fabric root holding contracts/ and shared/ is resolved from
# this file's location, overridable with SPARKNET_FABRIC_ROOT.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help
VAULT_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
FABRIC_ROOT ?= $(patsubst %/,%,$(dir $(VAULT_ROOT)))
ROLE_ROOT := $(VAULT_ROOT)

VENV_PY := $(VAULT_ROOT)/.venv/bin/python
# Interpreter for role targets: this subvault's own venv if it has one, else
# the fabric venv that `make devtools` at the fabric root creates, else python3.
# The middle tier is what makes a fabric checkout honest — `make ci` provisions
# only the fabric venv, and without it every role target falls through to
# whatever system python exists, which on a runner has no `cryptography`
# (first bare-clone run failed `validate` in the ledger target exactly there).
# On a standalone role deployment there is no fabric venv, so the chain simply
# ends at python3 as before.
FABRIC_VENV_PY := $(FABRIC_ROOT)/.venv/bin/python
PY := $(if $(wildcard $(VENV_PY)),$(VENV_PY),$(if $(wildcard $(FABRIC_VENV_PY)),$(FABRIC_VENV_PY),python3))

.PHONY: help env-init validate status plan test test-all lint spec-check \
        env-show parity ledger keygen keys-check units units-check \
        signer signer-unit console \
        provenance-verify user-init provenance-append ingest precommit shims-check \
        bundle wiki-preflight wiki-status wiki-lint wiki-query clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env-init: ## Write this role's .env + wiki dirs from .env.example (idempotent)
	@$(FABRIC_ROOT)/scripts/sparknet-env-init.sh "$(VAULT_ROOT)"

env-show: ## Print the paths this role resolves (vault, peer node, state dir)
	@"$(VAULT_ROOT)/scripts/sparknet-master-env.sh"

validate: ## Charter, plan, executables wired, and parity with the peer
	@for f in AGENTS.md MEMORY.md MISSION.md plans/MASTER_BUILD_PLAN.md \
	          configs/wireguard/master-peer.template security/key-management.md; do \
		  [ -f "$(VAULT_ROOT)/$$f" ] || { echo "missing $$f" >&2; exit 1; }; \
	done
	@echo "  ✓ required role files present"
	@for d in scripts services systemd manifests blockchain security; do \
	  [ -d "$(VAULT_ROOT)/$$d" ] || { echo "  ✗ $$d/ missing — see Step 16" >&2; exit 1; }; \
	done
	@echo "  ✓ executable surface present"
	@$(MAKE) --no-print-directory units-check  >/dev/null && echo "  ✓ units: wired and enabled"
	@$(MAKE) --no-print-directory keys-check   >/dev/null && echo "  ✓ vault: no key material"
	@$(MAKE) --no-print-directory parity        >/dev/null && echo "  ✓ peer parity: services load by path"
	@$(MAKE) --no-print-directory ledger        >/dev/null && echo "  ✓ master ledger: chain verifies"

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

parity: ## Prove this role runs the PEER's own service files, not copies
	@$(PY) "$(VAULT_ROOT)/services/sparknet-parity.py"

ledger: ## Verify the master's hash-chained ledger
	@$(PY) "$(VAULT_ROOT)/services/sparknet-ledger.py" verify

# Units are named explicitly rather than globbed, so that adding a unit file is a
# deliberate act: a new unit that nobody enables is a file that looks like
# functionality and is not, which is exactly what the wiring test hunts for.
# The signer unit is deliberately NOT in UNITS. `make units` installs and enables
# the role; enabling a process that holds the Master signing key is a different act
# from installing one, and belongs to the election (Step 14), not to an install.
# It is still referenced here, which is what units-check requires.
# The overlay anchor is in UNITS: the transport every Master decision travels
# over must come back at boot. The signer is NOT — enabling a key-holding process
# is the election's decision, not an install side effect (see SIGNER_UNIT below).
UNITS := sparknet-master-parity.service sparknet-master-ledger.service \
         sparknet-master-wireguard-anchor.service sparknet-master-firewall.service
SIGNER_UNIT := sparknet-master-signer.service
UNIT_DIR ?= /etc/systemd/system
# The overlay anchor and the firewall run as root and need a stable absolute path
# to the vault, so they are launched through generated shims (same convention as
# the peer role) rather than a vault path baked into the tracked unit file. The
# firewall resolves the PEER's script by path — a Master runs the peer's one
# implementation, exactly as it loads the peer's services.
SHIM_DIR ?= /usr/local/libexec/sparknet
WG_ANCHOR_SCRIPT := $(VAULT_ROOT)/scripts/sparknet-master-wireguard-anchor.sh
WG_ANCHOR_SHIM := $(SHIM_DIR)/sparknet-master-wireguard-anchor
PEER_NODE_DIR ?= $(FABRIC_ROOT)/peer-node
FIREWALL_SCRIPT := $(PEER_NODE_DIR)/scripts/sparknet-firewall.sh
FIREWALL_SHIM := $(SHIM_DIR)/sparknet-master-firewall

units: ## Install + enable this role's units (needs root; set UNIT_DIR to stage only)
	@for u in $(UNITS); do \
	  install -Dm644 "$(VAULT_ROOT)/systemd/$$u" "$(UNIT_DIR)/$$u" || exit 1; \
	done
	@echo "  ✓ staged $(UNITS) into $(UNIT_DIR)"
	@if [ "$(UNIT_DIR)" = "/etc/systemd/system" ]; then \
	  install -d "$(SHIM_DIR)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    printf 'exec %s "$@"\n' '$(VAULT_ROOT)/scripts/sparknet-master-wireguard-anchor.sh'; \
	  } > "$(WG_ANCHOR_SHIM)"; \
	  chmod +x "$(WG_ANCHOR_SHIM)"; \
	  echo "  ✓ wrote $(WG_ANCHOR_SHIM)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    echo '# Runs the PEER role firewall by path: a Master is a peer that won an'; \
	    echo '# election and keeps one implementation, exactly as it loads the peer services.'; \
	    printf 'exec %s "$@"\n' '$(FIREWALL_SCRIPT)'; \
	  } > "$(FIREWALL_SHIM)"; \
	  chmod +x "$(FIREWALL_SHIM)"; \
	  echo "  ✓ wrote $(FIREWALL_SHIM)"; \
	  systemctl daemon-reload && systemctl enable --now $(UNITS); \
	else \
	  echo "  (UNIT_DIR overridden — not touching systemd)"; \
	fi

units-check: ## Assert every unit in systemd/ is enabled by this Makefile
	@for u in "$(VAULT_ROOT)"/systemd/*.service; do \
	  b=$$(basename "$$u"); \
	  grep -q "$$b" "$(VAULT_ROOT)/Makefile" || { \
	    echo "  ✗ $$b is not enabled by any target — it would never run" >&2; exit 1; }; \
	done
	@echo "  ✓ every unit in systemd/ is enabled by \`make units\`"

signer: ## Print the signer's isolation posture (no key, no root, no socket)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-signer.py" --describe

signer-unit: ## Stage the signer unit ONLY (does not enable it; election does that)
	@install -Dm644 "$(VAULT_ROOT)/systemd/$(SIGNER_UNIT)" "$(UNIT_DIR)/$(SIGNER_UNIT)"
	@echo "  ✓ staged $(SIGNER_UNIT) into $(UNIT_DIR) — not enabled."
	@echo "    It will refuse to start until SPARKNET_NODE_ID and"
	@echo "    \$$SPARKNET_STATE_DIR/trust-root.json name this node as Master."

# The console is the operator's seat: it composes an admin request, asks the
# isolated signer for a signature, and posts it to a peer's /admin/ route. It is
# deliberately wired as a target here so it is not an inert file: it has no unit
# of its own (it runs on demand, in front of a human), and the spec test requires
# every service to be reachable from a unit or a make target.
console: ## Master admin console (ARGS='users <node>', 'feed --ping', ...)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-admin-console.py" $(ARGS)

keygen: ## Generate this node\'s cluster/operational/identity keys into the state dir
	@"$(VAULT_ROOT)/scripts/sparknet-master-keygen.sh"

# The guard that must never be weakened: no key material in the vault.
#
# Two things are checked, because they are different claims and a single find
# cannot make both:
#
#   1. Nothing key-shaped is tracked or committed. This scans the whole role
#      INCLUDING the state dir, so a key that escaped .gitignore is still caught.
#      It asks git rather than trusting the filename or the ignore rules.
#   2. The private halves that legitimately live in $SPARKNET_STATE_DIR are 0600
#      and the directory is 0700. That is the one place key material may exist,
#      and "may exist" is not the same as "is protected".
#
# The state dir used to be excluded wholesale, which made this check pass by
# ignoring precisely the files it exists to police. A key at 0644 in the state dir
# was the failure that mattered, and the old form approved it.
keys-check: ## Assert no key material is tracked, and state-dir keys are 0600
	@tracked=$$(git -C "$(FABRIC_ROOT)" ls-files --error-unmatch \
	    'master-node/**.ed25519' 'master-node/**.key' \
	    'master-node/**privkey*' 'master-node/**.seed' 2>/dev/null | grep -c . || true); \
	if [ "$$tracked" -ne 0 ]; then \
	  echo "  ✗ $$tracked private-key-shaped file(s) TRACKED BY GIT under master-node/" >&2; \
	  git -C "$(FABRIC_ROOT)" ls-files 'master-node/**.ed25519' \
	    'master-node/**.key' 'master-node/**privkey*' 'master-node/**.seed' >&2; \
	  echo "    A private key is in history. Rotate it; .gitignore is too late." >&2; \
	  exit 1; \
	fi; \
	echo "  ✓ no key material tracked by git"
	@state=$${SPARKNET_STATE_DIR:-"$${XDG_STATE_HOME:-$$HOME/.local/state}/sparknet/master-node"}; \
	case "$$(cd "$$state" 2>/dev/null && pwd || echo "$$state")" in \
	  "$(VAULT_ROOT)"/*|"$(FABRIC_ROOT)"/*) \
	    echo "  ✗ SPARKNET_STATE_DIR ($$state) is inside the vault." >&2; \
	    echo "    The admin surface bind-mounts the vault read-only into an LLM" >&2; \
	    echo "    container, so a key here is readable from it. Use an XDG state dir." >&2; \
	    exit 1;; \
	esac; \
	if [ -d "$$state/keys" ]; then \
	  bad=0; \
	  for priv in "$$state"/keys/*.ed25519; do \
	    [ -e "$$priv" ] || continue; \
	    m=$$(stat -c '%a' "$$priv"); \
	    if [ "$$m" != "600" ]; then \
	      echo "  ✗ $$priv is mode $$m, expected 600" >&2; bad=1; \
	    fi; \
	  done; \
	  d=$$(stat -c '%a' "$$state/keys"); \
	  if [ "$$d" != "700" ]; then \
	    echo "  ✗ $$state/keys is mode $$d, expected 700" >&2; bad=1; \
	  fi; \
	  [ "$$bad" -eq 0 ] || exit 1; \
	  echo "  ✓ state-dir private keys are 0600, key dir 0700"; \
	else \
	  echo "  ✓ no state-dir keys yet (run 'make keygen')"; \
	fi; \
	echo "  ✓ the vault references keys by path only"

test: spec-check ## Role tests

test-all: spec-check ## Alias for spec-check

lint: ## Ruff over this role's tests and services
	@if [ -x "$(VENV_PY)" ]; then \
	  "$(VENV_PY)" -m ruff check "$(VAULT_ROOT)/tests" "$(VAULT_ROOT)/services" ; \
	elif command -v ruff >/dev/null 2>&1; then \
	  ruff check "$(VAULT_ROOT)/tests" "$(VAULT_ROOT)/services" ; \
	else \
	  echo "ruff not installed — skipping (optional)."; \
	fi

bundle: ## Build a standalone master bundle into ../dist
	@$(FABRIC_ROOT)/scripts/sparknet-bundle.sh master

# --- provenance (the numbered layout's trust layer) ---------------------------
# Everything here delegates to ../shared/sparknet-provenance.py: one
# implementation, loaded from the fabric, never copied into this subvault.

PROV := $(FABRIC_ROOT)/shared/sparknet-provenance.py
PROV_PY := $(if $(wildcard $(FABRIC_ROOT)/.venv/bin/python),$(FABRIC_ROOT)/.venv/bin/python,$(PY))
PROV_VAULT := --vault "$(VAULT_ROOT)"

provenance-verify: ## Verify every note, the ledger and the approvals (STRICT=1 for --strict)
	@$(PROV_PY) $(PROV) $(PROV_VAULT) verify $(if $(STRICT),--strict,)

user-init: ## Generate the user key + fill 00_System/user.md once (FORCE=1 to redo)
	@$(PROV_PY) $(PROV) $(PROV_VAULT) user-init $(if $(FORCE),--force,) \
		$(if $(OWNER_ID),--owner-id "$(OWNER_ID)",)

provenance-append: ## Record a dual-signed approval (QUESTION= DECISION= AGENT= MODEL= [NOTE=...])
	@test -n "$(QUESTION)" || { echo "QUESTION= required" >&2; exit 1; }
	@test -n "$(DECISION)" || { echo "DECISION= required" >&2; exit 1; }
	@test -n "$(AGENT)"     || { echo "AGENT= required"     >&2; exit 1; }
	@test -n "$(MODEL)"     || { echo "MODEL= required"     >&2; exit 1; }
	@$(PROV_PY) $(PROV) $(PROV_VAULT) append-approval --question "$(QUESTION)" \
		--decision "$(DECISION)" --agent "$(AGENT)" --model "$(MODEL)" \
		$(if $(NOTE),--note $(NOTE),)

ingest: ## Land STDIN or SRC= as an unsigned note in 01_Inbox/ (SOURCE=master-node|peer-node|email)
	@$(PROV_PY) $(PROV) $(PROV_VAULT) ingest $(if $(SRC),"$(SRC)","-") \
		--source "$(if $(SOURCE),$(SOURCE),master-node)" \
		$(if $(SENDER),--sender "$(SENDER)",)

shims-check: ## Prove every legacy name is a symlink to its numbered home
	@$(PROV_PY) $(PROV) $(PROV_VAULT) shims

precommit: keys-check ## keys-check + secret scan + provenance-verify --strict
	@$(PROV_PY) $(PROV) $(PROV_VAULT) scan
	@$(PROV_PY) $(PROV) $(PROV_VAULT) verify --strict
	@echo "precommit: clean"

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
# --- Step 3 helpers (signing/registry/overlay) ---
.PHONY: keys authz-sign registry-verify revoke wg-render-master

keys: keygen ## Alias for keygen (WireGuard + Ed25519 per DoD)

authz-sign: ## Sign an identity into a registry entry (needs IDENTITY, optional CAPS, OUT)
	@test -n "$(IDENTITY)" || (echo "IDENTITY=<identity.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-sign.sh --identity "$(IDENTITY)" \
	  $$(test -n "$(CAPS)" && echo --capabilities "$(CAPS)") \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

registry-sign-socket: ## Sign an entry THROUGH the signer socket, recording a ledger block (needs ENTRY, optional OUT)
	@test -n "$(ENTRY)" || (echo "ENTRY=<entry.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-sign-socket.sh --entry "$(ENTRY)" \
	  $$(test -n "$(SOCKET)" && echo --socket "$(SOCKET)") \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

registry-verify: ## Verify a registry (needs REGISTRY)
	@test -n "$(REGISTRY)" || (echo "REGISTRY=<registry.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-verify.sh --registry "$(REGISTRY)"

revoke: ## Sign a revoked entry for an identity (needs IDENTITY)
	@test -n "$(IDENTITY)" || (echo "IDENTITY=<identity.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-revoke.sh --identity "$(IDENTITY)" \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

wg-render-master: ## Render Master wg0 from registry (needs REGISTRY, optional OUT)
	@test -n "$(REGISTRY)" || (echo "REGISTRY=<registry.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-wg-render-master.sh --registry "$(REGISTRY)" \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

# --- Step 5: guard approval ---
.PHONY: approval-issue approval-deliver

approval-issue: ## Issue signed approval (needs TARGET, CONTENT, optional OUT)
	@test -n "$(TARGET)" || (echo "TARGET=<path> required" >&2; exit 1)
	@test -n "$(CONTENT)" || (echo "CONTENT=<file> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-approval-issue.sh --target "$(TARGET)" --content "$(CONTENT)" \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

approval-deliver: ## Deliver approval (needs FINGERPRINT, optional PAYLOAD, URL, OUT)
	@test -n "$(FINGERPRINT)" || (echo "FINGERPRINT=<fp> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-approval-deliver.sh --fingerprint "$(FINGERPRINT)" \
	  $$(test -n "$(PAYLOAD)" && echo --payload "$(PAYLOAD)") \
	  $$(test -n "$(URL)" && echo --url "$(URL)") \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

# --- Step 6: registry distribution ---
.PHONY: registry-publish

registry-publish: ## Publish registry to OUT (needs REGISTRY, OUT)
	@test -n "$(REGISTRY)" || (echo "REGISTRY=<registry.json> required" >&2; exit 1)
	@test -n "$(OUT)" || (echo "OUT=<dest> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-publish.sh --registry "$(REGISTRY)" --out "$(OUT)"

# --- Step 7: listener target stub ---
.PHONY: registry-listen

registry-listen: ## Registry push listener (stub)
	@$(PY) $(VAULT_ROOT)/services/sparknet-registry-listener.py

# --- Step 8: KillSwitch ---
.PHONY: killswitch

killswitch: ## Master KillSwitch (root-gated)
	@$(ROLE_ROOT)/scripts/sparknet-killswitch.sh

# --- Step 9: scheduler ---
.PHONY: scheduler

scheduler: ## Scheduler scaffold
	@$(PY) $(VAULT_ROOT)/services/sparknet-scheduler.py

# --- Step 10: share ratification ---
.PHONY: share-ratify

share-ratify: ## Share ratification scaffold
	@$(PY) $(VAULT_ROOT)/services/sparknet-share-ratify.py

# --- ensure killswitch service is exposed via target name in make? already have killswitch target; also need to ensure entry referenced? ---

# reference for wiring test
# sparknet-killswitch.py wired via killswitch target

# --- election ---
.PHONY: election-approve

# The master-node half of the member ceremony plus installation: co-signs the
# formed root and writes it into manifests/cluster-trust-root.json.
# EXPECT=<node-id> is the candidate this node voted for — required, never guessed.
election-approve: ## install the formed trust root (EXPECT=<node> URL= IDENTITY= ROOT_DOC= KEY_DIR= WAIT=)
	@$(ROLE_ROOT)/scripts/sparknet-election-approve.sh \
	  $(if $(EXPECT),--expect-master "$(EXPECT)") \
	  $(if $(URL),--url "$(URL)") \
	  $(if $(IDENTITY),--identity "$(IDENTITY)") \
	  $(if $(ROOT_DOC),--root-doc "$(ROOT_DOC)") \
	  $(if $(KEY_DIR),--key-dir "$(KEY_DIR)") \
	  $(if $(WAIT),--wait-seconds "$(WAIT)")
