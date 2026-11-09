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

EVENT ?= -
TRUST_NODE ?=
LEVEL ?=
REASON ?=

.PHONY: help env-init validate status plan test test-all lint spec-check \
        env-show parity ledger evidence-capture review-agents keygen keys-check units units-check step89-admin \
        signer signer-unit reflex-unit peer-intake-unit rfi-responder-unit wg-observer-unit nocturnal-probe-unit console vault-health vault-heal \
        provenance-verify user-init provenance-append ingest precommit shims-check context-pack context-check governance-check \
        bundle wiki-preflight wiki-status wiki-lint wiki-query skills-sync skills-check vector-reindex vector-serve uplift-intake uplift-intake-unit uplift-intake-check distill distill-doctor distill-trainer-help distill-dataset distill-run distill-status file-share-serve nat-status-serve share-ratify-unit share-ratify-serve share-ratify-list share-ratify-approve share-ratify-refuse clean

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

env-init: ## Write this role's .env + wiki dirs from .env.example (idempotent)
	@$(FABRIC_ROOT)/scripts/sparknet-env-init.sh "$(VAULT_ROOT)"

env-show: ## Print the paths this role resolves (vault, peer node, state dir)
	@"$(VAULT_ROOT)/scripts/sparknet-master-env.sh"

VECTOR_PY ?= $(FABRIC_ROOT)/.venv-vector/bin/python
VECTOR_STATE ?= $(HOME)/.local/state/sparknet/master-node/vector
QDRANT_URL ?= http://127.0.0.1:6333

RATIFY_STATE ?= $(HOME)/.local/state/sparknet/master-node/share-ratify/queue.json
RATIFY_KEYS ?= $(HOME)/.local/state/sparknet/master-node/share-keys
SIGNER_SOCKET ?= $(HOME)/.local/state/sparknet/master-node/signer/signer.sock

share-ratify-unit: ## Render the 4203 queue unit to stdout (stage only; never enables)
	@$(ROLE_ROOT)/scripts/sparknet-share-ratify-unit.sh

share-ratify-serve: ## Run the 4203 queue in the foreground (needs RATIFY_KEYS)
	@$(PY) "$(ROLE_ROOT)/services/sparknet-share-ratify.py" --serve --bind "$${SPARKNET_RATIFY_BIND:-127.0.0.1}" --port "$${SPARKNET_RATIFY_PORT:-4203}" --state "$(RATIFY_STATE)" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --trusted-key-dir "$(RATIFY_KEYS)"

share-ratify-list: ## Print the 4203 pending/decided queue
	@$(PY) "$(ROLE_ROOT)/services/sparknet-share-ratify.py" --list --state "$(RATIFY_STATE)"

share-ratify-approve: ## Approve one queued share (SHARE_ID=...; signs through the signer)
	@test -n "$(SHARE_ID)" || { echo "SHARE_ID required" >&2; exit 2; }
	@$(PY) "$(ROLE_ROOT)/services/sparknet-share-ratify.py" --state "$(RATIFY_STATE)" --signer-socket "$(SIGNER_SOCKET)" --approve "$(SHARE_ID)"

share-ratify-refuse: ## Refuse one queued share (SHARE_ID=...; signs through the signer)
	@test -n "$(SHARE_ID)" || { echo "SHARE_ID required" >&2; exit 2; }
	@$(PY) "$(ROLE_ROOT)/services/sparknet-share-ratify.py" --state "$(RATIFY_STATE)" --signer-socket "$(SIGNER_SOCKET)" --refuse "$(SHARE_ID)"

vector-reindex: ## Rebuild sparknet-fabric and sparknet-shared in the 4223 Qdrant store
	@test -x "$(VECTOR_PY)" || { echo "vector-reindex: $(VECTOR_PY) missing (make vector-dev in a separate venv)"; exit 2; }
	@SPARKNET_QDRANT_URL="$(QDRANT_URL)" $(VECTOR_PY) "$(FABRIC_ROOT)/scripts/sparknet-vector.py" fabric index --vault "$(FABRIC_ROOT)" --data-dir "$(VECTOR_STATE)/fabric"
	@SPARKNET_QDRANT_URL="$(QDRANT_URL)" $(VECTOR_PY) "$(FABRIC_ROOT)/scripts/sparknet-vector.py" shared index --vault "$(ROLE_ROOT)" --data-dir "$(VECTOR_STATE)/shared"

vector-serve: ## Run the signed 4223 listener in the foreground (needs VECTOR_PY/key)
	@test -x "$(VECTOR_PY)" || { echo "vector-serve: $(VECTOR_PY) missing"; exit 2; }
	@SPARKNET_QDRANT_URL="$(QDRANT_URL)" $(VECTOR_PY) "$(ROLE_ROOT)/services/sparknet-vector-serve.py" --fabric-vault "$(FABRIC_ROOT)" --shared-vault "$(ROLE_ROOT)" --state-root "$(VECTOR_STATE)" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --bind "$${SPARKNET_VECTOR_BIND:-127.0.0.1}" --port "$${SPARKNET_VECTOR_PORT:-4223}" --trusted-key "$${SPARKNET_VECTOR_TRUSTED_KEY:?set NODE_ID=PATH}"

UPLIFT_STATE ?= /srv/sparknet/uplift
DISTILL_STATE ?= /srv/sparknet/distill
DISTILL_CONFIG ?= $(ROLE_ROOT)/configs/distill.json

uplift-intake: ## Run the signed 8091 uplift intake in the foreground (no key, no signer)
	@$(PY) "$(ROLE_ROOT)/services/sparknet-uplift-intake.py" --serve --bind "$${SPARKNET_UPLIFT_BIND:-127.0.0.1}" --port "$${SPARKNET_UPLIFT_PORT:-8091}" --state "$(UPLIFT_STATE)" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --trusted-key "$${SPARKNET_UPLIFT_TRUSTED_KEY:?set NODE_ID=PATH}"

uplift-intake-unit: ## Stage the 8091 uplink unit ONLY (never enables it)
	@install -Dm644 "$(VAULT_ROOT)/systemd/sparknet-uplift-intake.service" "$(UNIT_DIR)/sparknet-uplift-intake.service"
	@echo "  ✓ staged sparknet-uplift-intake.service into $(UNIT_DIR) — not enabled"

uplift-intake-check: ## Validate the 8091 registry/keyring without listening
	@$(PY) "$(ROLE_ROOT)/services/sparknet-uplift-intake.py" --check --state "$(UPLIFT_STATE)" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --trusted-key "$${SPARKNET_UPLIFT_TRUSTED_KEY:?set NODE_ID=PATH}"

distill-trainer-help: ## Show the LoRA trainer launcher contract
	@$(ROLE_ROOT)/scripts/sparknet-distill-trainer.sh --help

distill-doctor: ## Check the GPU/trainer prerequisites for a distillation run
	@$(PY) "$(ROLE_ROOT)/services/sparknet-distill.py" doctor --config "$(DISTILL_CONFIG)" --state "$(DISTILL_STATE)"

distill-dataset: ## Build a same-family distillation dataset from uplifted traces
	@$(PY) "$(ROLE_ROOT)/services/sparknet-distill.py" dataset --config "$(DISTILL_CONFIG)" --state "$(DISTILL_STATE)" --uplift "$(UPLIFT_STATE)"

distill-status: ## Write the sanitized distillation status snapshot for the WebUI
	@$(PY) "$(ROLE_ROOT)/services/sparknet-distill-status.py" --config "$(DISTILL_CONFIG)" --state "$(DISTILL_STATE)" --out "$(ROLE_ROOT)/.state/webui/distill-status.json" --share-out /srv/sparknet/share/learning/status.json

distill: ## Show the run scaffold (operator-triggered; no training by default)
	@$(PY) "$(ROLE_ROOT)/services/sparknet-distill.py" run --config "$(DISTILL_CONFIG)" --state "$(DISTILL_STATE)" --uplift "$(UPLIFT_STATE)"

distill-run: ## Train a configured teacher->student candidate (requires DISTILL_EXECUTE=1)
	@test "$${DISTILL_EXECUTE:-0}" = "1" || { echo "distill-run: set DISTILL_EXECUTE=1 and SPARKNET_DISTILL_TRAINER"; exit 2; }
	@$(PY) "$(ROLE_ROOT)/services/sparknet-distill.py" run --execute --sign --config "$(DISTILL_CONFIG)" --state "$(DISTILL_STATE)" --uplift "$(UPLIFT_STATE)"

file-share-serve: ## Run the read-only 4221 file share (needs a trusted peer key)
	@$(PY) "$(ROLE_ROOT)/services/sparknet-file-share.py" --root "$${SPARKNET_SHARE_ROOT:-/srv/sparknet/share}" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --bind "$${SPARKNET_SHARE_BIND:-127.0.0.1}" --port "$${SPARKNET_SHARE_PORT:-4221}" --trusted-key "$${SPARKNET_SHARE_TRUSTED_KEY:?set NODE_ID=PATH}"

nat-status-serve: ## Run the read-only 4222 NAT status/dry-run surface
	@$(PY) "$(ROLE_ROOT)/services/sparknet-nat-status.py" --registry "$(ROLE_ROOT)/manifests/node-authorizations.json" --bind "$${SPARKNET_NAT_BIND:-127.0.0.1}" --port "$${SPARKNET_NAT_PORT:-4222}" --trusted-key "$${SPARKNET_NAT_TRUSTED_KEY:?set NODE_ID=PATH}"

context-pack: ## Regenerate this role's CONTEXT.md
	@$(PY) $(FABRIC_ROOT)/scripts/sparknet-context-pack.py --root "$(VAULT_ROOT)" --role master

governance-check: ## Enforce the five-file shape and budgets
	@$(PY) $(FABRIC_ROOT)/scripts/sparknet-governance-check.py

context-check: ## Fail if this role's CONTEXT.md is stale
	@$(PY) $(FABRIC_ROOT)/scripts/sparknet-context-pack.py --root "$(VAULT_ROOT)" --role master --check

validate: ## Charter, plan, executables wired, and parity with the peer
	@for f in AGENTS.md CONTEXT.md MEMORY.md MISSION.md INTENT.md PLAN.md \
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
	@grep -m1 '^current:' "$(VAULT_ROOT)/PLAN.md" \
	  || { echo "PLAN.md has no 'current:' cursor" >&2; exit 1; }
	@printf '\n  steps done: %s of %s\n' \
	  "$$(grep -c '^- \[x\]' "$(VAULT_ROOT)/PLAN.md")" \
	  "$$(grep -c '^- \[ \]' "$(VAULT_ROOT)/PLAN.md")"

# Prints the block for whichever step the `current:` cursor points at.
plan: ## Print the active plan step with its DoD
	@cursor="$$(grep -m1 '^current:' "$(VAULT_ROOT)/PLAN.md" \
	           | sed 's/.*current:[[:space:]]*//')"; \
	if [ "$$cursor" = "done" ]; then echo "plan is terminal: current: done"; exit 0; fi; \
	awk -v want="$$cursor" \
	  '/^## Step /{ inside = (index($$0, "Step " want) > 0) } \
	   inside { print }' "$(VAULT_ROOT)/PLAN.md"

spec-check: ## Assert the spec/impl boundary has not rotted
	@$(PY) -m pytest "$(VAULT_ROOT)/tests" -q

parity: ## Prove this role runs the PEER's own service files, not copies
	@$(PY) "$(VAULT_ROOT)/services/sparknet-parity.py"

ledger: ## Verify the master's hash-chained ledger
	@$(PY) "$(VAULT_ROOT)/services/sparknet-ledger.py" verify

evidence-capture: ## Capture one evidence event from EVENT (JSON file, - for stdin)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-evidence-capture.py" --event "$(EVENT)"

step89-admin: ## Compose/apply signed Step 89 writes (lake, collab, distill, packages)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-step89-admin.py" $(ARGS)

review-agents: ## Review EVENT, or emit a trust transition (TRUST_NODE= LEVEL= REASON=)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-review-agents.py" --event "$(EVENT)" \
		$(if $(TRUST_NODE),--trust-node "$(TRUST_NODE)" --level "$(LEVEL)" --reason "$(REASON)",)

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
# The reflex broker is opt-in (local-only is the default) and needs a credential
# provisioned in Step 64F, so it is staged, not enabled. units-check still sees
# it here, which is what keeps the unit from being forgotten.
REFLEX_UNIT := sparknet-reflex-broker.service
# The peer-intake listener (8090, re-scoped by fabric Step 69C) is staged, not
# enabled, like the signer and reflex broker: a peer-facing socket on the
# authority-plane node is an operator's decision to bring up.
PEER_INTAKE_UNIT := sparknet-peer-intake.service
RFI_RESPONDER_UNIT := sparknet-rfi-responder.service
# The root WireGuard observer is staged with its timer, not enabled: a root
# one-minute timer is an operator decision and Step 9G owns the live window.
WG_OBSERVER_UNITS := sparknet-wg-observer.service sparknet-wg-observer.timer
WG_OBSERVER_SHIM := $(SHIM_DIR)/sparknet-wg-observer
NOCTURNAL_PROBE_UNITS := sparknet-nocturnal-probe.service sparknet-nocturnal-probe.timer
NOCTURNAL_PROBE_SHIM := $(SHIM_DIR)/sparknet-nocturnal-probe
# The delivery service must NOT be enabled with --now: its first run would push
# to whatever peers exist at install time, and a single unreachable peer (a
# normal condition) would make `make units` fail. The timer owns the schedule;
# the service is pulled in by it.
REGISTRY_UNITS := sparknet-registry-deliver.service sparknet-registry-deliver.timer
REGISTRY_TIMER := sparknet-registry-deliver.timer
# The task orchestrator is staged but not enabled: it is a new event-plane
# service and goes live only in the Step 89 rollout window.
ORCHESTRATOR_UNIT := sparknet-orchestrator.service
# The private image registry is staged, not enabled: it needs an operator-created
# token and is loopback-only.
CONTAINER_REGISTRY_UNIT := sparknet-container-registry.service
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
	@for u in $(UNITS) $(REGISTRY_UNITS) $(ORCHESTRATOR_UNIT); do \
	  install -Dm644 "$(VAULT_ROOT)/systemd/$$u" "$(UNIT_DIR)/$$u" || exit 1; \
	done
	@echo "  ✓ staged $(UNITS) into $(UNIT_DIR)"
	@if [ "$(UNIT_DIR)" = "/etc/systemd/system" ]; then \
	  install -d "$(SHIM_DIR)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    printf 'exec %s "$$@"\n' '$(VAULT_ROOT)/scripts/sparknet-master-wireguard-anchor.sh'; \
	  } > "$(WG_ANCHOR_SHIM)"; \
	  chmod +x "$(WG_ANCHOR_SHIM)"; \
	  echo "  ✓ wrote $(WG_ANCHOR_SHIM)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    echo '# Runs the PEER role firewall by path: a Master is a peer that won an'; \
	    echo '# election and keeps one implementation, exactly as it loads the peer services.'; \
	    printf 'exec %s "$$@"\n' '$(FIREWALL_SCRIPT)'; \
	  } > "$(FIREWALL_SHIM)"; \
	  chmod +x "$(FIREWALL_SHIM)"; \
	  echo "  ✓ wrote $(FIREWALL_SHIM)"; \
	  systemctl daemon-reload && systemctl enable --now $(UNITS) && \
	  systemctl enable --now $(REGISTRY_TIMER); \
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

container-registry-unit: ## Stage the private registry unit ONLY (does not enable it)
	@install -Dm644 "$(VAULT_ROOT)/systemd/$(CONTAINER_REGISTRY_UNIT)" "$(UNIT_DIR)/$(CONTAINER_REGISTRY_UNIT)"
	@echo "  ✓ staged $(CONTAINER_REGISTRY_UNIT) into $(UNIT_DIR) — not enabled."
	@echo "    Create \$$SPARKNET_STATE_DIR/registry-token (0600) before starting it."

reflex-unit: ## Stage the reflex broker unit ONLY (does not enable it; 64F does)
	@install -Dm644 "$(VAULT_ROOT)/systemd/$(REFLEX_UNIT)" "$(UNIT_DIR)/$(REFLEX_UNIT)"
	@echo "  ✓ staged $(SIGNER_UNIT) into $(UNIT_DIR) — not enabled."
	@echo "    It will refuse to start until SPARKNET_NODE_ID and"
	@echo "    \$$SPARKNET_STATE_DIR/trust-root.json name this node as Master."

vault-health: ## Diagnose the vault (read-only; writes 00_System/vault-health.json)
	@$(PY) $(FABRIC_ROOT)/scripts/sparknet-vault-health.py --root "$(VAULT_ROOT)"

vault-heal: ## Safe derived repairs only
	@$(PY) $(FABRIC_ROOT)/scripts/sparknet-vault-health.py --root "$(VAULT_ROOT)" --repair

rfi-respond: ## Answer queued RFI requests once (OFFLINE=1 for a test; DRY_RUN=1 to print)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-rfi-responder.py" --once \
	  $(if $(OFFLINE),--offline) $(if $(DRY_RUN),--dry-run) $(if $(URL),--url "$(URL)") \
	  $(if $(REGISTRY),--registry "$(REGISTRY)") $(if $(JSON),--json)

rfi-responder-unit: ## Stage the RFI responder unit ONLY (does not enable it)
	@install -Dm644 "$(VAULT_ROOT)/systemd/$(RFI_RESPONDER_UNIT)" "$(UNIT_DIR)/$(RFI_RESPONDER_UNIT)"
	@echo "  ✓ staged $(RFI_RESPONDER_UNIT) into $(UNIT_DIR) — not enabled."

peer-intake-unit: ## Stage the peer-intake (8090) unit ONLY (does not enable it)
	@install -Dm644 "$(VAULT_ROOT)/systemd/$(PEER_INTAKE_UNIT)" "$(UNIT_DIR)/$(PEER_INTAKE_UNIT)"
	@echo "  ✓ staged $(PEER_INTAKE_UNIT) into $(UNIT_DIR) — not enabled."
	@echo "    It binds 10.100.0.1:8090 and refuses a non-overlay bind; enabling a"
	@echo "    peer-facing socket on the authority-plane node is an operator decision."

wg-observer-unit: ## Stage the root WG observer + timer ONLY (does not enable them)
	@for u in $(WG_OBSERVER_UNITS); do \
	  install -Dm644 "$(VAULT_ROOT)/systemd/$$u" "$(UNIT_DIR)/$$u" || exit 1; \
	done
	@if [ "$(UNIT_DIR)" = "/etc/systemd/system" ]; then \
	  install -d "$(SHIM_DIR)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    printf 'exec %s "%s" "$$@"\n' '$(PY)' '$(VAULT_ROOT)/services/sparknet-wg-observer.py'; \
	  } > "$(WG_OBSERVER_SHIM)"; \
	  chmod +x "$(WG_OBSERVER_SHIM)"; \
	  echo "  ✓ wrote $(WG_OBSERVER_SHIM)"; \
	fi
	@echo "  ✓ staged $(WG_OBSERVER_UNITS) into $(UNIT_DIR) — not enabled."
	@echo "    The observer runs as root, reads wg1/wg0, and writes /mnt/log/sparknet-wg.json."

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

precommit: keys-check skills-check ## keys-check + skill manifest + secret scan + provenance-verify --strict
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

skills-sync: ## Rebuild this role's local skill catalog
	@$(PY) $(FABRIC_ROOT)/scripts/sync-role-skills.py --apply --role master

skills-check: ## Verify this role's skill catalog, licenses and manifest
	@$(PY) $(FABRIC_ROOT)/scripts/sync-role-skills.py --check --role master

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
.PHONY: approval-issue approval-deliver approval-sign-socket

approval-issue: ## Issue signed approval (needs TARGET, CONTENT, PEER_FINGERPRINT or IDENTITY; optional TTL_SECONDS, OUT)
	@test -n "$(TARGET)" || (echo "TARGET=<path> required" >&2; exit 1)
	@test -n "$(CONTENT)" || (echo "CONTENT=<file> required" >&2; exit 1)
	@test -n "$(PEER_FINGERPRINT)$(IDENTITY)" || (echo "PEER_FINGERPRINT=<fp> or IDENTITY=<identity.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-approval-issue.sh --target "$(TARGET)" --content "$(CONTENT)" \
	  $$(test -n "$(PEER_FINGERPRINT)" && echo --peer-fingerprint "$(PEER_FINGERPRINT)") \
	  $$(test -n "$(IDENTITY)" && echo --identity "$(IDENTITY)") \
	  $$(test -n "$(TTL_SECONDS)" && echo --ttl-seconds "$(TTL_SECONDS)") \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

approval-deliver: ## Deliver approval to a peer (needs FINGERPRINT, APPROVAL; optional REGISTRY, URL, OUT)
	@test -n "$(FINGERPRINT)" || (echo "FINGERPRINT=<fp> required" >&2; exit 1)
	@test -n "$(APPROVAL)" || (echo "APPROVAL=<approval.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-approval-deliver.sh --fingerprint "$(FINGERPRINT)" \
	  --approval "$(APPROVAL)" \
	  $$(test -n "$(REGISTRY)" && echo --registry "$(REGISTRY)") \
	  $$(test -n "$(URL)" && echo --url "$(URL)") \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

approval-sign-socket: ## Sign an approval THROUGH the isolated signer (needs APPROVAL, optional OUT)
	@test -n "$(APPROVAL)" || (echo "APPROVAL=<approval.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-approval-sign-socket.sh --approval "$(APPROVAL)" \
	  $$(test -n "$(OUT)" && echo --out "$(OUT)")

# --- Step 6: registry distribution ---
.PHONY: registry-publish registry-deliver

# Sign+emit the publication the peers install. `--out` holds `current.json`;
# the sequence makes an older publication refuse at every peer, so a re-run
# cannot roll a peer back.
registry-publish: ## Publish registry to OUT (needs REGISTRY, optional OUT/SEQUENCE/OFFLINE)
	@test -n "$(REGISTRY)" || (echo "REGISTRY=<registry.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-publish.sh --registry "$(REGISTRY)" \
	  $(if $(OUT),--out "$(OUT)") \
	  $(if $(SEQUENCE),--sequence "$(SEQUENCE)") \
	  $(if $(OFFLINE),--offline)

# Push the *already signed* publication to every peer's guard. No key is needed
# here: delivery is not signing, and a peer that missed an earlier push is
# converged by re-running this (or by the timer installed by `make units`).
registry-deliver: ## Push a published registry to peers (needs PUBLICATION; optional PEER/TIMEOUT)
	@test -n "$(PUBLICATION)" || (echo "PUBLICATION=<current.json> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-registry-deliver.sh --publication "$(PUBLICATION)" \
	  $(if $(PEER),--peer "$(PEER)") \
	  $(if $(TIMEOUT),--timeout "$(TIMEOUT)")

# --- fabric Step 67D: RFI answer intake ---
.PHONY: rfi-answer

# Compose, sign and deliver one RFI answer into a peer's 01_Inbox (the Master half
# of contracts/rfi-schema.json). Signing goes through the isolated signer by
# default; OFFLINE=1 signs with the operational key in-process (tests, or a host
# with no signer running). The peer installs it on POST /api/v1/rfi (guard, 9090).
rfi-answer: ## Sign+deliver an RFI answer (needs REQUEST_ID, PEER, ITEM_NAME, and CONTENT or EMPTY)
	@test -n "$(REQUEST_ID)" || (echo "REQUEST_ID=<id> required" >&2; exit 1)
	@test -n "$(PEER)" || (echo "PEER=<fingerprint> required" >&2; exit 1)
	@test -n "$(ITEM_NAME)" || (echo "ITEM_NAME=<name> required" >&2; exit 1)
	@$(ROLE_ROOT)/scripts/sparknet-rfi-answer.sh --request-id "$(REQUEST_ID)" \
	  --peer "$(PEER)" --item-name "$(ITEM_NAME)" \
	  $(if $(CONTENT),--content "$(CONTENT)") \
	  $(if $(EMPTY),--empty) \
	  $(if $(URL),--url "$(URL)") \
	  $(if $(REGISTRY),--registry "$(REGISTRY)") \
	  $(if $(OFFLINE),--offline) \
	  $(if $(OUT),--out "$(OUT)")

# --- Step 7: 8090 — re-scoped by fabric Step 69C ---
# The instant-push/pull listener stub is retired: Step 6 pushes the signed registry
# Master→peer on 9090, so a Master-side ACL-push listener was never needed. 8090 is
# now the peer→Master intake (telemetry evidence and, from fabric Step 70B, RFI
# requests). See `peer-intake-unit` above and MASTER_OBSERVABILITY_DESIGN.md.

# --- Step 8: KillSwitch ---
.PHONY: killswitch

killswitch: ## Master cluster KillSwitch; dry-run by default, FORCE=1 to engage (root)
	@$(ROLE_ROOT)/scripts/sparknet-killswitch.sh $(if $(FORCE),--force,)

# --- Step 9: scheduler ---
.PHONY: scheduler

scheduler: ## Nocturnal scheduler CLI (ARGS='plan|arm ...|status|abort ...'; default --help)
	@$(PY) "$(VAULT_ROOT)/services/sparknet-scheduler.py" $(if $(ARGS),$(ARGS),--help)

scheduler-status: ## Show the nocturnal lease state and current readiness
	@$(PY) "$(VAULT_ROOT)/services/sparknet-scheduler.py" status

nocturnal-probe-unit: ## Stage the probe-only nocturnal service + timer (does not enable)
	@for u in $(NOCTURNAL_PROBE_UNITS); do \
	  install -Dm644 "$(VAULT_ROOT)/systemd/$$u" "$(UNIT_DIR)/$$u" || exit 1; \
	done
	@if [ "$(UNIT_DIR)" = "/etc/systemd/system" ]; then \
	  install -d "$(SHIM_DIR)"; \
	  { echo '#!/bin/sh'; \
	    echo '# Generated by master-node/Makefile — do not edit.'; \
	    echo 'set -a'; \
	    echo '. "$(VAULT_ROOT)/.env" 2>/dev/null || true'; \
	    echo 'set +a'; \
	    printf 'exec %s "%s" status --notify "$$@"\n' '$(PY)' '$(VAULT_ROOT)/services/sparknet-scheduler.py'; \
	  } > "$(NOCTURNAL_PROBE_SHIM)"; \
	  chmod +x "$(NOCTURNAL_PROBE_SHIM)"; \
	  echo "  ✓ wrote $(NOCTURNAL_PROBE_SHIM)"; \
	fi
	@echo "  ✓ staged $(NOCTURNAL_PROBE_UNITS) into $(UNIT_DIR) — not enabled."

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
