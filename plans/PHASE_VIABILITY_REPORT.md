# Phase Viability Report

## Phase 0 - Save Google Doc + Planning Docs
Status: FULFILLED ✓
Viability Tests: Files exist, content intact, traceability established. All pass.

## Phase 1 - Push to GitHub (BEFORE changes)
Status: PREPARATORY FULFILLED; REMOTE PUSH BLOCKED BY EXTERNAL AUTH
Viability Tests: Repo initialized, commits clean, remote configured, blocker documented. Preparatory work complete.

## Phase 2 - Ingest & Distill Materials
Status: FULFILLED ✓
Viability Tests: Knowledge structure, concepts, raxxar context integrated. All pass.

## Phase 3 - Vault/Path/VEnv-Agnostic Design
Status: FULFILLED ✓
Viability Tests: Env wrappers work correctly (SPARKNET_* exported), design doc complete. All pass.

## Phase 4 - Build DGX Spark Node Template (MVI)
Status: FULFILLED ✓ (with Minimal Viable Implementations)
Viability Tests: now automated in `tests/test_scripts.py` — see below.

## Phase 5 - Documentation, Validation & Integration
Status: FULFILLED ✓
Viability Tests: All docs present, validate/provision run end-to-end successfully.

---

## Correction (2026-10-04, first pass)

Phase 4's "viability tests" were **manual dry-run checks, not automated tests**.
The ✓ marks recorded that a command exited successfully on one machine on one
day. They did not assert behaviour, and nothing re-ran them.

## Correction (2026-10-04, second pass)

Every one of those manual checks is now a test in `tests/test_scripts.py`, and
each asserts **no mutation** by hashing the whole tree before and after — so
"exit 0" alone can never pass. The guard is no longer a stub.

### Automated (`make test` — 189 tests)

| File | Tests | Covers |
|---|---|---|
| `test_containment.py` | 9 | no hardcoded vault path; `install-config.sh` has no write primitive; every unit calls a shim the installer actually generates, and system units never use `%h` |
| `test_env.py` | 7 | env resolves from `BASH_SOURCE` from any cwd; relocated vault resolves to itself |
| `test_services.py` | 20 | dependency allow-list; services run from a relocated copy; guard is no longer a stub; guard writes only via atomic replace and never uses a shell |
| `test_manifests.py` | 10 | every protected path has provenance; wireguard is now mapped; rendered sources must exist |
| `test_wireguard.py` | 31 | template placeholders, render output, key shape, `/32` enforcement, dry-run purity, no private keys anywhere in the source tree, keygen Ed25519 output is usable by the signer |
| `test_authz.py` | 33 | SHA-256 fingerprint stability, Ed25519 verify, tamper on identity/capabilities/overlay/expiry, revocation, master-key-only signing, private-key loading in all three encodings |
| `test_guard.py` | 34 | approval verification, replay/expiry, capability gating, arming/root refusal, audit ledger integrity, **overlay source authorization** |
| `test_scripts.py` | 45 | every Phase 4 dry-run asserted + tree-fingerprint no-mutation; syntax of every `.sh` and `.py`; `--help` on every CLI |

### Phase 4 checks, now asserted

| Manual check (was ✓) | Now |
|---|---|
| `sync.sh --dry-run` | structured log lines + tree unchanged, and the non-dry-run path is still a no-op |
| `wlan-guard.sh --dry-run` | exits 0, emits the `10.100.0.1` Master-only policy, tree unchanged |
| `killswitch.sh --dry-run` | exits 1 with "requires root" as non-root; help documents `ROOT-GATED`; tree unchanged |
| `guard-d.py --check-manifest` | 9 protected paths, provenance complete — **and** fails when provenance is deliberately removed |
| `dispatch-bridge.py --health` | health OK, all 7 PPE states present |
| `dispatch-bridge.py --test-approval` | appends only to a relocated copy; real ledger byte-identical; hash chain links via `prev_hash`/`block_hash` with consecutive indexes |
| identity capture + provision | capture is stable across runs, privilege boundary recorded, provision runs end-to-end against a copy |
| Python/bash syntax | every `scripts/*.sh`, every `systemd/*.sh`, every `services/*.py` |

### Closed since the first correction

- **`sparknet-guard-d.py` is real.** It verifies Ed25519 approvals, enforces
  replay/expiry, checks the target against the protected manifest, requires the
  signed `guard-apply` capability, refuses without root and without explicit
  arming, binds only the overlay, applies atomically with `chattr -i`/`+i`, and
  writes a hash-chained audit ledger. The old test that pinned the stub state has
  been replaced by one that fails if the guard becomes a stub again.
- **`/etc/wireguard/wg0.conf` now has a vault source.** It moved out of
  `source_of_truth.unmapped` into `generated`, rendered from
  `configs/wireguard/wg0-node.conf.template` by
  `scripts/sparknet-wireguard-render.sh`. `tests/test_manifests.py` asserts the
  map *and* fails if the renderer or template disappears.
- **Phase 4's one-offs are automated.** See the table above.
- **`cryptography>=42` is declared** in `requirements.txt` and `pyproject.toml`;
  the dependency allow-list is asserted so it cannot silently grow.
- **Three real bugs were found and fixed while writing the tests above.** Each
  has a regression test that was verified to fail against the old code:
  1. *The guard rejected the Master.* The server binds the node's overlay
     address, so a legitimate request arrives with the **Master's** source
     address, but the check compared against the node's own address — every
     genuine Master request would have been refused with 403. It now permits
     loopback plus `10.100.0.1` (read from `security-policies.json`), and
     explicitly refuses the node's own address so a local process cannot spoof.
  2. *Root systemd units could never start.* They used `%h/.local/bin`, which
     under the **system** manager resolves to `/root/.local/bin` — a directory
     the invoking user's install never creates. System units now call
     `/usr/local/libexec/sparknet/`, and user units keep `%h/.local/bin`. The
     installer generates both sets.
  3. *keygen and the signer disagreed on key encoding.* keygen documented an
     Ed25519 keypair but emitted only WireGuard keys; once added, it wrote raw
     bytes while `sign --master-key` base64-decoded the file as text, so signing
     died with `UnicodeDecodeError`. keygen now writes base64 (matching the
     vault's `.b64` convention) and `load_private_key()` accepts base64, raw 32
     bytes, or hex.
- **The key-hygiene scan covers the whole source tree**, not just `git ls-files`.
  New work is untracked by definition, so a tracked-files-only scan silently
  skipped every file written during this session.

### Still NOT enforced — known gaps

- **No CI.** The suite runs only when a human invokes `make test`.
- **No live WireGuard / root verification.** The dev host has no `wg`,
  `wg-quick`, `nft`, no WireGuard kernel module and no `CAP_NET_ADMIN`.
  Unproven on real hardware: live handshake, `PersistentKeepalive` behaviour,
  `chattr +i` enforcement, nftables egress rules, KillSwitch teardown/recovery.
  `tests/test_guard.py` covers refusal and dry-run paths only; the **live apply
  path has never executed**. See the checklist at the end of
  `docs/wireguard.md`.
- **No usable Master keypair.** `manifests/keys/master-ed25519.pub.b64` was
  generated with a discarded private key, so it cannot sign. The registry ships
  empty, which is intentional (no node gets privileges by default), but real
  provisioning must supply a Master keypair.
- **Provisioning has been exercised end-to-end but not on real hardware.** A
  stub `wg` produced key material, the Master key signed a real entry, and the
  peer verified it with only the public key (`allowed: true`), then refused a
  tampered capability set (`bad_signature`). What remains unproven is a genuine
  `wg`/`wg-quick`, a real registry distribution channel, and the systemd units
  being started by a running systemd.
- **`deployment/netplan/*.yaml` are placeholders** — self-described
  "hypothetical template" with empty `ethernets: {}` / `wifis: {}`. They are
  not real host configs.
- **`agents/*/agent.py` are stubs** and `agents/*.service` run `/bin/true`.
- **Git push is blocked**, and a credential that was once committed in plaintext
  must be rotated and purged from history before any push. See
  `GITHUB_PUSH_BLOCKER.md`.