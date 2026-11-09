#!/usr/bin/env python3
"""Nocturnal batch-lease scheduler — Step 9C state machine and 9G dispatcher.

The fleet has no RDMA and no shared GPU address space. The useful part of Step 9
is not a pooled-memory fabric; it is a time-boxed lease over independent nodes
that are demonstrably idle. This process owns the thresholds and the all-nodes
conjunction. It never runs a job, opens a socket, signs, grants, revokes or
signals a peer.

The authoritative WireGuard evidence is the root observer's snapshot
(``services/sparknet-wg-observer.py``). Peer-pushed counters are advisory and are
deliberately ignored: the unprivileged peer service cannot read ``wg show`` on
this userspace-WireGuard fleet. Interactive-session and GPU evidence still come
from the peers' telemetry, and from the same local probes for the Master.

CLI::

    sparknet-scheduler.py plan
    sparknet-scheduler.py arm --plan-id <id> --confirm <id> --reason <text>
    sparknet-scheduler.py status
    sparknet-scheduler.py abort --reason <text>

Default is dry-run: ``plan`` and ``arm`` dispatch nothing; the separate
``dispatch`` verb requires an ARMED lease and asks the isolated signer for the
job signature. No verb can skip the two-step confirmation. A
missing, stale, duplicated, unreadable or revoked signal is busy, never idle.
Design: ``master-node/plans/NOCTURNAL_BATCH_DESIGN.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time as time_module
import urllib.error
import urllib.request
from collections.abc import Sequence
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
AUTHZ_PATH = REPO_ROOT / "shared" / "sparknet-authz.py"
IDLE_PATH = REPO_ROOT / "shared" / "sparknet-idle.py"
CLUSTER_PATH = REPO_ROOT / "shared" / "sparknet-cluster.py"
NOCTURNAL_PATH = REPO_ROOT / "shared" / "sparknet-nocturnal.py"

SCHEMA_VERSION = "sparknet-nocturnal/1"
STATE_SCHEMA_VERSION = "sparknet-nocturnal-state/1"
EVIDENCE_SCHEMA_VERSION = "sparknet-nocturnal-evidence/1"

SAMPLES_REQUIRED = 3
TELEMETRY_CADENCE_SECONDS = 300
TELEMETRY_JITTER_SECONDS = 60
MIN_SAMPLE_GAP_SECONDS = 60
MAX_SAMPLE_GAP_SECONDS = TELEMETRY_CADENCE_SECONDS + TELEMETRY_JITTER_SECONDS
SAMPLE_MAX_AGE_SECONDS = MAX_SAMPLE_GAP_SECONDS
OBSERVER_CADENCE_SECONDS = 60
OBSERVER_MAX_AGE_SECONDS = 180
GPU_MAX_PCT = 5.0
WG_BYTES_PER_MINUTE_FLOOR = 1024 * 1024
PLAN_TTL_SECONDS = 600
LOCAL_HISTORY_LIMIT = 20
LEASE_MAX_MINUTES = 120
WINDOW_START = time(2, 0)
WINDOW_END = time(5, 0)
HARD_STOP = time(6, 0)
ALLOWED_CLOCK_SKEW_SECONDS = 300

DEFAULT_TELEMETRY_SPOOL = Path("/mnt/log/sparknet-telemetry.jsonl")
DEFAULT_OBSERVER_SNAPSHOT = Path("/mnt/log/sparknet-wg.json")


class SchedulerError(Exception):
    """A refusal the CLI can report without pretending a plan exists."""


def _load_module(path: Path, name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SchedulerError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _authz() -> Any:
    return _load_module(AUTHZ_PATH, "sparknet_scheduler_authz")


def _idle() -> Any:
    return _load_module(IDLE_PATH, "sparknet_scheduler_idle")


def _cluster() -> Any:
    return _load_module(CLUSTER_PATH, "sparknet_scheduler_cluster")


def _nocturnal() -> Any:
    return _load_module(NOCTURNAL_PATH, "sparknet_scheduler_nocturnal")


def _now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def default_state_dir() -> Path:
    explicit = os.environ.get("SPARKNET_NOCTURNAL_STATE", "").strip()
    if explicit:
        return Path(explicit)
    state = os.environ.get("SPARKNET_STATE_DIR", "").strip()
    if state:
        return Path(state) / "nocturnal"
    home = os.environ.get("XDG_STATE_HOME", "").strip()
    if home:
        return Path(home) / "sparknet" / "master-node" / "nocturnal"
    return Path.home() / ".local" / "state" / "sparknet" / "master-node" / "nocturnal"


def default_registry() -> Path:
    explicit = os.environ.get("SPARKNET_NOCTURNAL_REGISTRY", "").strip()
    if explicit:
        return Path(explicit)
    telemetry = os.environ.get("SPARKNET_TELEMETRY_REGISTRY", "").strip()
    if telemetry:
        return Path(telemetry)
    return ROLE_ROOT / "manifests" / "node-authorizations.json"


def default_spool() -> Path:
    explicit = os.environ.get("SPARKNET_TELEMETRY_SPOOL", "").strip()
    return Path(explicit) if explicit else DEFAULT_TELEMETRY_SPOOL


def default_snapshot() -> Path:
    explicit = os.environ.get("SPARKNET_WG_SNAPSHOT", "").strip()
    return Path(explicit) if explicit else DEFAULT_OBSERVER_SNAPSHOT


def _atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(value, sort_keys=True, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        temp.unlink(missing_ok=True)
        raise


# --- signed registry, roster and attribution ----------------------------------


def _bare(address: Any) -> str:
    return str(address or "").split("/", 1)[0].strip()


def load_registry(path: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Read the registry and verify every non-revoked entry before using it.

    The scheduler is not an authority, but it must not place a job for a node the
    signed registry cannot attest. A malformed, unsigned or identity-mismatched
    entry refuses the whole plan; one bad entry is not silently dropped.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerError(f"registry_unreadable: {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("authorizations"), list):
        raise SchedulerError("registry_malformed")
    authz = _authz()
    try:
        public_key = authz.public_key_from_b64(str(document.get("master_public_key_b64") or ""))
    except Exception as exc:
        raise SchedulerError("registry_master_key_invalid") from exc

    nodes: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    seen_keys: set[str] = set()
    seen_addresses: set[str] = set()
    moment = now or datetime.now(timezone.utc)
    for entry in document["authorizations"]:
        if not isinstance(entry, dict):
            raise SchedulerError("registry_entry_malformed")
        fingerprint = entry.get("fingerprint")
        identity = entry.get("identity")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise SchedulerError("registry_fingerprint_malformed")
        if not isinstance(identity, dict):
            raise SchedulerError("registry_identity_malformed")
        try:
            if authz.fingerprint(identity) != fingerprint:
                raise SchedulerError("registry_identity_mismatch")
        except SchedulerError:
            raise
        except Exception as exc:
            raise SchedulerError("registry_identity_malformed") from exc
        if not authz.verify_signature(
            public_key, str(entry.get("signature_b64") or ""), authz.authorization_message(entry)
        ):
            raise SchedulerError(f"registry_bad_signature: {fingerprint[:12]}")
        caps = entry.get("capabilities")
        if not isinstance(caps, list):
            raise SchedulerError("registry_capabilities_malformed")
        unknown = [cap for cap in caps if cap not in authz.KNOWN_CAPABILITIES]
        if unknown:
            raise SchedulerError("registry_unknown_capability")
        if entry.get("revoked"):
            continue
        expires = parse_ts(entry.get("expires_at"))
        issued = parse_ts(entry.get("issued_at"))
        if expires is not None and moment >= expires:
            continue
        if issued is not None and moment < issued - timedelta(seconds=ALLOWED_CLOCK_SKEW_SECONDS):
            raise SchedulerError(f"registry_not_yet_valid: {fingerprint[:12]}")
        node_id = identity.get("node_id")
        key = identity.get("wireguard_public_key_b64")
        node_pubkey_b64 = entry.get("node_pubkey_b64")
        role = identity.get("role")
        address = _bare(entry.get("overlay_ipv4") or identity.get("overlay_ipv4"))
        if not isinstance(node_id, str) or not node_id:
            raise SchedulerError("registry_node_id_missing")
        if not isinstance(key, str) or not key:
            raise SchedulerError("registry_wireguard_key_missing")
        if role not in {"master", "peer"}:
            raise SchedulerError(f"registry_role_malformed: {node_id}")
        if not address:
            raise SchedulerError(f"registry_overlay_missing: {node_id}")
        if fingerprint in seen_fingerprints or key in seen_keys or address in seen_addresses:
            raise SchedulerError("registry_duplicate_node")
        seen_fingerprints.add(fingerprint)
        seen_keys.add(key)
        seen_addresses.add(address)
        nodes.append(
            {
                "fingerprint": fingerprint,
                "node_id": node_id,
                "role": role,
                "wireguard_public_key_b64": key,
                "overlay_ipv4": address,
                "capabilities": sorted(caps),
                "node_pubkey_b64": node_pubkey_b64,
            }
        )
    nodes.sort(key=lambda node: node["node_id"])
    if sum(1 for node in nodes if node["role"] == "master") > 1:
        raise SchedulerError("registry_multiple_masters")
    return {"document": document, "nodes": nodes}


def roster_digest(nodes: Sequence[dict[str, Any]]) -> str:
    projection = [
        {
            "fingerprint": node["fingerprint"],
            "node_id": node["node_id"],
            "role": node["role"],
            "wireguard_public_key_b64": node["wireguard_public_key_b64"],
            "overlay_ipv4": node["overlay_ipv4"],
        }
        for node in nodes
    ]
    payload = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# --- telemetry evidence -------------------------------------------------------


def read_telemetry(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SchedulerError("telemetry_unreadable") from exc
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchedulerError(f"telemetry_malformed_line: {number}") from exc
        if not isinstance(row, dict):
            raise SchedulerError(f"telemetry_malformed_line: {number}")
        rows.append(row)
    return rows


def _nonce_reasons(rows: Sequence[dict[str, Any]], fingerprints: set[str]) -> list[str]:
    seen: set[str] = set()
    for row in rows:
        if row.get("peer_fingerprint") not in fingerprints:
            continue
        nonce = row.get("nonce")
        if not isinstance(nonce, str) or not nonce:
            continue
        if nonce in seen:
            return ["telemetry_replayed_nonce"]
        seen.add(nonce)
    return []


def _idle_reasons(idle: Any, *, ignore_wireguard_errors: bool = True) -> tuple[datetime | None, list[str]]:
    if not isinstance(idle, dict):
        return None, ["idle_missing"]
    if idle.get("schema_version") != "sparknet-idle/1":
        return None, ["idle_schema_malformed"]
    sampled = parse_ts(idle.get("sampled_at"))
    if sampled is None:
        return None, ["idle_sampled_at_missing"]
    reasons: list[str] = []
    errors = idle.get("errors")
    if not isinstance(errors, list):
        reasons.append("idle_errors_malformed")
    else:
        for error in errors:
            if not isinstance(error, str):
                reasons.append("idle_errors_malformed")
            elif ignore_wireguard_errors and error.startswith("wireguard_"):
                continue
            else:
                reasons.append(f"probe:{error}")
    interactive = idle.get("interactive_sessions")
    ssh = idle.get("ssh_sessions")
    if isinstance(interactive, bool) or not isinstance(interactive, int) or interactive != 0:
        reasons.append("interactive_sessions_busy")
    if isinstance(ssh, bool) or not isinstance(ssh, int) or ssh != 0:
        reasons.append("ssh_sessions_busy")
    gpu = idle.get("gpu_util_pct")
    if isinstance(gpu, bool) or not isinstance(gpu, (int, float)):
        reasons.append("gpu_evidence_missing")
    elif float(gpu) > GPU_MAX_PCT:
        reasons.append("gpu_busy")
    if not isinstance(idle.get("gpu_probe"), str) or not idle.get("gpu_probe"):
        reasons.append("gpu_probe_missing")
    return sampled, reasons


def _samples_reasons(
    samples: Sequence[dict[str, Any]],
    *,
    now: datetime,
    ignore_wireguard_errors: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Evaluate the last three samples; any busy or gap resets the count."""
    if len(samples) < SAMPLES_REQUIRED:
        return [], ["insufficient_samples"]
    selected = list(samples[-SAMPLES_REQUIRED:])
    reasons: list[str] = []
    parsed: list[tuple[datetime, list[str]]] = []
    for sample in selected:
        sampled, sample_reasons = _idle_reasons(sample, ignore_wireguard_errors=ignore_wireguard_errors)
        if sampled is None:
            reasons.extend(reason for reason in sample_reasons if reason not in reasons)
            continue
        if sampled > now + timedelta(seconds=ALLOWED_CLOCK_SKEW_SECONDS):
            reasons.append("sample_from_future")
        parsed.append((sampled, sample_reasons))
        reasons.extend(reason for reason in sample_reasons if reason not in reasons)
    if len(parsed) != SAMPLES_REQUIRED:
        return [], reasons or ["insufficient_samples"]
    for index in range(1, len(parsed)):
        gap = (parsed[index][0] - parsed[index - 1][0]).total_seconds()
        if gap < MIN_SAMPLE_GAP_SECONDS:
            reasons.append("sample_gap_too_short")
        elif gap > MAX_SAMPLE_GAP_SECONDS:
            reasons.append("sample_gap_too_long")
    age = (now - parsed[-1][0]).total_seconds()
    if age > SAMPLE_MAX_AGE_SECONDS:
        reasons.append("sample_stale")
    evidence = []
    for sample in selected:
        sampled, sample_reasons = _idle_reasons(sample, ignore_wireguard_errors=ignore_wireguard_errors)
        evidence.append(
            {
                "sampled_at": _now_iso(sampled) if sampled else None,
                "idle": not sample_reasons,
                "reasons": sample_reasons,
            }
        )
    return evidence, reasons


def peer_evidence(node: dict[str, Any], rows: Sequence[dict[str, Any]], now: datetime) -> dict[str, Any]:
    samples = [
        row for row in rows if row.get("kind") == "metrics" and row.get("peer_fingerprint") == node["fingerprint"]
    ]
    reasons: list[str] = []
    for row in samples:
        source = _bare(row.get("source"))
        if source != node["overlay_ipv4"]:
            reasons.append("telemetry_source_mismatch")
            break
    # Keep a malformed/missing payload in the sequence. Dropping it would let
    # three clean samples on either side of an unreadable report pass the gate.
    payloads = []
    for row in samples:
        payload = row.get("payload")
        payloads.append(payload.get("idle") if isinstance(payload, dict) else None)
    evidence, sample_reasons = _samples_reasons(payloads, now=now, ignore_wireguard_errors=True)
    reasons.extend(reason for reason in sample_reasons if reason not in reasons)
    return {
        "source": "peer_telemetry",
        "samples": evidence,
        "idle": not reasons,
        "reasons": reasons,
    }


def local_evidence(history: Sequence[dict[str, Any]], now: datetime) -> dict[str, Any]:
    evidence, reasons = _samples_reasons(history, now=now, ignore_wireguard_errors=True)
    return {
        "source": "master_local",
        "samples": evidence,
        "idle": not reasons,
        "reasons": reasons,
    }


# --- observer evidence --------------------------------------------------------


def observer_evidence(
    snapshot_path: Path,
    nodes: Sequence[dict[str, Any]],
    now: datetime,
    *,
    current_boot_id: str | None,
) -> dict[str, Any]:
    reasons: list[str] = []
    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"source": "master_observer", "idle": False, "reasons": ["observer_missing"]}
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != "sparknet-wg-observer/1":
        return {"source": "master_observer", "idle": False, "reasons": ["observer_malformed"]}
    errors = snapshot.get("errors")
    if errors:
        reasons.append("observer_error")
    if not current_boot_id or snapshot.get("boot_id") != current_boot_id:
        reasons.append("observer_boot_changed")
    if not isinstance(snapshot.get("interface"), str) or not snapshot.get("interface"):
        reasons.append("observer_interface_missing")
    sampled = parse_ts(snapshot.get("sampled_at"))
    if sampled is None:
        reasons.append("observer_sampled_at_missing")
    elif (sampled - now).total_seconds() > ALLOWED_CLOCK_SKEW_SECONDS:
        reasons.append("observer_from_future")
    elif (now - sampled).total_seconds() > OBSERVER_MAX_AGE_SECONDS:
        reasons.append("observer_stale")
    history = snapshot.get("history")
    if not isinstance(history, list) or len(history) < 2:
        reasons.append("observer_insufficient_samples")
        history = []
    latest = history[-1] if history else None
    previous = history[-2] if len(history) >= 2 else None
    if not isinstance(latest, dict) or not isinstance(previous, dict):
        reasons.append("observer_insufficient_samples")
        latest = previous = None

    expected = {node["wireguard_public_key_b64"]: node for node in nodes if node["role"] != "master"}
    if not expected:
        reasons.append("no_peer_roster")
    current_peers: dict[str, dict[str, Any]] = {}
    previous_peers: dict[str, dict[str, Any]] = {}
    for label, sample, target in (("latest", latest, current_peers), ("previous", previous, previous_peers)):
        if not isinstance(sample, dict):
            continue
        rows = sample.get("peers")
        if not isinstance(rows, list):
            reasons.append(f"observer_{label}_malformed")
            continue
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("public_key_b64"), str):
                reasons.append(f"observer_{label}_malformed")
                continue
            if row["public_key_b64"] in target:
                reasons.append("observer_duplicate_peer")
            target[row["public_key_b64"]] = row
    unknown = set(current_peers) - set(expected)
    if unknown:
        reasons.append("observer_unknown_peer")
    latest_at = parse_ts(latest.get("sampled_at")) if isinstance(latest, dict) else None
    previous_at = parse_ts(previous.get("sampled_at")) if isinstance(previous, dict) else None
    interval = (latest_at - previous_at).total_seconds() if latest_at and previous_at else 0.0
    if latest_at and previous_at and interval <= 0:
        reasons.append("observer_time_reversed")
    if latest_at and previous_at and interval > OBSERVER_MAX_AGE_SECONDS:
        reasons.append("observer_gap_too_long")
    max_bytes_per_second = WG_BYTES_PER_MINUTE_FLOOR / 60.0
    for key in expected:
        if key not in current_peers or key not in previous_peers:
            reasons.append("observer_peer_missing")
            continue
        current = current_peers[key]
        before = previous_peers[key]
        try:
            current_total = int(current["rx_bytes"]) + int(current["tx_bytes"])
            previous_total = int(before["rx_bytes"]) + int(before["tx_bytes"])
        except (KeyError, TypeError, ValueError):
            reasons.append("observer_counter_malformed")
            continue
        if current_total < previous_total:
            reasons.append("observer_counter_reset")
            continue
        if interval > 0 and (current_total - previous_total) / interval > max_bytes_per_second:
            reasons.append("wireguard_busy")
    return {
        "source": "master_observer",
        "interface": snapshot.get("interface"),
        "sampled_at": snapshot.get("sampled_at"),
        "sample_interval_seconds": interval,
        "idle": not reasons,
        "reasons": reasons,
    }


# --- the all-nodes conjunction ------------------------------------------------


def build_evidence(
    registry: dict[str, Any],
    rows: Sequence[dict[str, Any]],
    snapshot_path: Path,
    local_history: Sequence[dict[str, Any]],
    now: datetime,
    *,
    current_boot_id: str | None,
) -> dict[str, Any]:
    nodes = registry["nodes"]
    fingerprints = {node["fingerprint"] for node in nodes}
    global_reasons = _nonce_reasons(rows, fingerprints)
    observer = observer_evidence(snapshot_path, nodes, now, current_boot_id=current_boot_id)
    local = local_evidence(local_history, now)
    if not local["idle"]:
        global_reasons.extend(reason for reason in local["reasons"] if reason not in global_reasons)
    if not observer["idle"]:
        global_reasons.extend(reason for reason in observer["reasons"] if reason not in global_reasons)

    node_evidence: list[dict[str, Any]] = []
    for node in nodes:
        evidence = local if node["role"] == "master" else peer_evidence(node, rows, now)
        entry = {
            "fingerprint": node["fingerprint"],
            "node_id": node["node_id"],
            "role": node["role"],
            "overlay_ipv4": node["overlay_ipv4"],
            "wireguard_public_key_b64": node["wireguard_public_key_b64"],
            "evidence": evidence,
        }
        if not evidence["idle"]:
            global_reasons.extend(reason for reason in evidence["reasons"] if reason not in global_reasons)
        node_evidence.append(entry)
    if not any(node["role"] != "master" for node in nodes) and "no_peer_roster" not in global_reasons:
        global_reasons.append("no_peer_roster")
    evidence = {
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evaluated_at": _now_iso(now),
        "roster": node_evidence,
        "roster_digest": roster_digest(nodes),
        "local": local,
        "observer": observer,
        "ready": not global_reasons,
        "reasons": global_reasons,
    }
    evidence["evidence_digest"] = canonical_digest(evidence)
    return evidence


# --- state and lease lifecycle ------------------------------------------------


def default_state() -> dict[str, Any]:
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "state": "DISARMED",
        "updated_at": _now_iso(),
        "plan": None,
        "lease": None,
        "local_history": [],
        "last_reasons": [],
    }


def load_state(state_dir: Path) -> dict[str, Any]:
    path = state_dir / "state.json"
    if not path.exists():
        return default_state()
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchedulerError("state_unreadable") from exc
    if not isinstance(state, dict) or state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise SchedulerError("state_malformed")
    for field_name in ("state", "local_history"):
        if field_name not in state:
            raise SchedulerError("state_malformed")
    if state["state"] not in {"DISARMED", "PROBING", "ARMED", "DRAINING", "CLOSED"}:
        raise SchedulerError("state_malformed")
    if not isinstance(state["local_history"], list):
        raise SchedulerError("state_malformed")
    return state


def save_state(state_dir: Path, state: dict[str, Any], now: datetime) -> None:
    state["updated_at"] = _now_iso(now)
    _atomic_json(state_dir / "state.json", state)


def append_event(
    state_dir: Path,
    *,
    action: str,
    state: str,
    now: datetime,
    reason: str = "",
    plan_id: str | None = None,
    lease_id: str | None = None,
) -> None:
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    event = {
        "at": _now_iso(now),
        "action": action,
        "state": state,
        "reason": reason,
        "plan_id": plan_id,
        "lease_id": lease_id,
    }
    path = state_dir / "events.jsonl"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def lease_window(now: datetime) -> tuple[datetime, datetime]:
    local = now.astimezone()
    start = datetime.combine(local.date(), WINDOW_START, tzinfo=local.tzinfo)
    end = datetime.combine(local.date(), WINDOW_END, tzinfo=local.tzinfo)
    hard = datetime.combine(local.date(), HARD_STOP, tzinfo=local.tzinfo)
    if local >= end:
        raise SchedulerError("outside_window")
    lease_start = max(local, start)
    lease_end = min(lease_start + timedelta(minutes=LEASE_MAX_MINUTES), end, hard)
    if lease_end <= lease_start:
        raise SchedulerError("outside_window")
    return lease_start, lease_end


def make_plan(
    evidence: dict[str, Any],
    *,
    now: datetime,
    lease_start: datetime,
    lease_end: datetime,
    plan_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_id": plan_id or f"plan-{secrets.token_hex(8)}",
        "created_at": _now_iso(now),
        "expires_at": _now_iso(now + timedelta(seconds=PLAN_TTL_SECONDS)),
        "roster_digest": evidence["roster_digest"],
        "evidence_digest": evidence["evidence_digest"],
        "lease": {
            "start_at": _now_iso(lease_start),
            "expires_at": _now_iso(lease_end),
            "max_minutes": LEASE_MAX_MINUTES,
            "window": "02:00-05:00 local",
            "hard_stop": "06:00 local",
        },
        "assignments": [],
        "evidence": evidence,
    }


def _operator(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    for name in ("SUDO_USER", "USER", "LOGNAME"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    raise SchedulerError("operator_required")


def _current_boot_id() -> str | None:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _append_local(state: dict[str, Any], now: datetime, interface: str | None) -> None:
    idle = _idle()
    try:
        sample = idle.collect_idle_evidence(now=now, interface=interface)
    except Exception as exc:
        sample = {
            "schema_version": "sparknet-idle/1",
            "sampled_at": _now_iso(now),
            "interactive_sessions": None,
            "ssh_sessions": None,
            "gpu_probe": None,
            "gpu_util_pct": None,
            "wg_interface": interface,
            "wg_rx_bytes": None,
            "wg_tx_bytes": None,
            "wg_peer_count": None,
            "errors": [f"idle_probe_failed:{type(exc).__name__}"],
        }
    history = list(state.get("local_history") or [])
    history.append(sample)
    state["local_history"] = history[-LOCAL_HISTORY_LIMIT:]


def _append_local_if_due(state: dict[str, Any], now: datetime, interface: str | None) -> None:
    """Take a fresh Master sample, unless the last one is still inside the gap.

    Arming immediately after planning must not create two samples seconds apart:
    that would make the three-sample gate fail on its own freshness check. Reuse
    the plan sample until it is at least ``MIN_SAMPLE_GAP_SECONDS`` old.
    """
    history = state.get("local_history") or []
    last = history[-1] if history and isinstance(history[-1], dict) else None
    last_at = parse_ts(last.get("sampled_at")) if isinstance(last, dict) else None
    if last_at is not None and (now - last_at).total_seconds() < MIN_SAMPLE_GAP_SECONDS:
        return
    _append_local(state, now, interface)


def _refusal(state_dir: Path, state: dict[str, Any], now: datetime, reasons: Sequence[str]) -> None:
    state["last_reasons"] = list(reasons)
    save_state(state_dir, state, now)


def _close_lease(state: dict[str, Any], now: datetime, reason: str) -> None:
    lease = state.get("lease")
    if isinstance(lease, dict):
        lease["ended_at"] = _now_iso(now)
        lease["end_reason"] = reason
    state["state"] = "CLOSED"


def _emit(value: Any) -> None:
    print(json.dumps(value, sort_keys=True, indent=2))


def _load_inputs(args: argparse.Namespace, now: datetime) -> dict[str, Any]:
    return {
        "registry": load_registry(Path(args.registry), now=now),
        "rows": read_telemetry(Path(args.telemetry)),
        "snapshot": Path(args.snapshot),
        "boot_id": _current_boot_id(),
    }


def _default_signer_socket() -> Path:
    state = os.environ.get("SPARKNET_STATE_DIR", "").strip()
    if state:
        return Path(state) / "signer" / "signer.sock"
    return Path.home() / ".local" / "state" / "sparknet" / "master-node" / "signer" / "signer.sock"


def _recv_line(connection: socket.socket, max_bytes: int = 1 << 20) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > max_bytes:
            raise SchedulerError("signer_response_too_large")
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


class SchedulerSigner:
    def __init__(self, socket_path: str | Path, *, timeout: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def call(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.socket_path.exists():
            raise SchedulerError(f"no-signer: {self.socket_path}")
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(json.dumps(payload).encode("utf-8") + b"\n")
            line = _recv_line(connection)
        except OSError as exc:
            raise SchedulerError(f"signer-error: {exc}") from exc
        finally:
            connection.close()
        try:
            response = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise SchedulerError("signer-protocol") from exc
        if not isinstance(response, dict):
            raise SchedulerError("signer-protocol")
        return response

    def root_id(self) -> str:
        response = self.call({"op": "root-id"})
        if not response.get("ok"):
            raise SchedulerError(str(response.get("error") or "signer-refused"))
        return str(response["root_id"])

    def sign_job(self, job: dict[str, Any]) -> dict[str, Any]:
        response = self.call({"op": "sign-cluster-job", "root_id": self.root_id(), "job": job})
        if not response.get("ok"):
            raise SchedulerError(str(response.get("error") or "signer-refused"))
        signed = response.get("job")
        if not isinstance(signed, dict):
            raise SchedulerError("signer-protocol")
        return signed


def _http_json(url: str, payload: dict[str, Any] | None = None, *, timeout: float = 30.0) -> tuple[int, dict[str, Any]]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
    request.add_header("Accept", "application/json")
    if data is not None:
        request.add_header("Content-Type", "application/json")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"ok": False, "error": raw}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise SchedulerError(f"http-error: {exc}") from exc


def _master_node_id() -> str:
    explicit = os.environ.get("SPARKNET_NODE_ID", "").strip()
    if explicit:
        return explicit
    path = ROLE_ROOT / "manifests" / "master-identity.json"
    try:
        return str(json.loads(path.read_text(encoding="utf-8"))["node_id"])
    except Exception as exc:
        raise SchedulerError("master_identity_unreadable") from exc


def _ensure_nocturnal_git(work_tree: Path, git_dir: Path) -> Path:
    """Initialize the state-dir artifact repository on first use."""
    if not git_dir.exists():
        git_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        subprocess.run(
            ["git", f"--git-dir={git_dir}", f"--work-tree={work_tree}", "init", "-q"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", f"--git-dir={git_dir}", "config", "user.email", "sparknet-master@localhost"],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", f"--git-dir={git_dir}", "config", "user.name", "sparknet-master"],
            check=True,
            capture_output=True,
            text=True,
        )
    return git_dir


def _dispatch(args: argparse.Namespace, now: datetime) -> int:
    """Dispatch one signed job through the existing peer cluster ingress.

    This does not grant anything. It requires an ARMED lease, asks the isolated
    signer for a cluster-job signature, dispatches over the existing overlay
    ingress, verifies every participant result against the registry-bound node
    key, then writes the reduced aggregate under the Master vault.
    """
    state_dir = Path(args.state_dir)
    state = load_state(state_dir)
    if state.get("state") != "ARMED" or not isinstance(state.get("lease"), dict):
        raise SchedulerError("no_active_lease")
    lease = state["lease"]
    active_lease_id = str(lease.get("lease_id") or "")
    if not active_lease_id:
        raise SchedulerError("lease_id_missing")
    if args.lease_id and args.lease_id != active_lease_id:
        raise SchedulerError("lease_id_mismatch")
    lease_expires = parse_ts(lease.get("expires_at"))
    if lease_expires is None or now >= lease_expires:
        raise SchedulerError("lease_expired")
    lease_id = active_lease_id
    registry = load_registry(Path(args.registry), now=now)
    nodes = registry["nodes"]
    master_id = _master_node_id()
    if lease.get("roster_digest") != roster_digest(nodes):
        raise SchedulerError("roster_changed")
    roster = sorted({master_id, *[str(node["node_id"]) for node in nodes]})
    governance = "peer_pair" if len(roster) == 2 else "master_governed"
    cluster = _cluster()
    job_doc = json.loads(Path(args.job).read_text(encoding="utf-8"))
    if isinstance(job_doc, dict) and isinstance(job_doc.get("job"), dict):
        job_doc = job_doc["job"]
    if not isinstance(job_doc, dict):
        raise SchedulerError("job_malformed")
    built = cluster.construct(job_doc, roster, governance_mode=governance)
    signer = SchedulerSigner(args.signer_socket or _default_signer_socket())
    signed_job = signer.sign_job(job_doc)
    by_id = {str(node["node_id"]): node for node in nodes}
    collected: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    result_docs: list[dict[str, Any]] = []
    for assignment in built["placement"]["assignments"]:
        node_id = assignment["node_id"]
        if node_id == master_id:
            raise SchedulerError("master_subtasks_not_supported")
        node = by_id.get(node_id)
        if node is None:
            raise SchedulerError(f"unknown_node: {node_id}")
        if "cluster-serve" not in node.get("capabilities", []):
            raise SchedulerError(f"cluster_serve_missing: {node_id}")
        if not node.get("node_pubkey_b64"):
            raise SchedulerError(f"node_pubkey_missing: {node_id}")
        endpoint = f"http://{_bare(node['overlay_ipv4'])}:4096"
        status, response = _http_json(endpoint + "/v1/cluster/submit", {"job": signed_job, "lease_id": lease_id})
        if status != 200 or not response.get("ok"):
            reason = response.get("reason") or response.get("error") or status
            raise SchedulerError(f"dispatch_refused: {node_id}: {reason}")
        job_id = str(response.get("job_id") or signed_job["job_id"])
        deadline = time_module.monotonic() + float(args.timeout)
        record: dict[str, Any] = {}
        while time_module.monotonic() < deadline:
            status, record = _http_json(endpoint + f"/v1/cluster/status/{job_id}")
            if status != 200:
                raise SchedulerError(f"status_refused: {node_id}: {status}")
            if record.get("status") in ("completed", "failed", "cancelled"):
                break
            time_module.sleep(2)
        if record.get("status") != "completed":
            detail = f"{record.get('status')} {record.get('error') or ''}".strip()
            raise SchedulerError(f"job_not_completed: {node_id}: {detail}")
        status, result_doc = _http_json(endpoint + f"/v1/cluster/result/{job_id}")
        if status != 200 or not result_doc.get("ok"):
            raise SchedulerError(f"result_refused: {node_id}: {status}")
        payload = result_doc.get("result") or {}
        results = payload.get("results") if isinstance(payload, dict) else None
        manifest = payload.get("manifest") if isinstance(payload, dict) else None
        if not isinstance(results, list) or not isinstance(manifest, dict):
            raise SchedulerError(f"result_malformed: {node_id}")
        nocturnal = _nocturnal()
        for result in results:
            if not nocturnal.verify_result(result, str(node["node_pubkey_b64"])):
                raise SchedulerError(f"result_signature_invalid: {node_id}")
        if not nocturnal.verify_manifest(manifest, str(node["node_pubkey_b64"])):
            raise SchedulerError(f"manifest_signature_invalid: {node_id}")
        collected.extend(results)
        manifests.append(manifest)
        result_docs.append(payload)
    reduced = cluster.reduce_results(collected, [item["subtask_id"] for item in built["subtasks"]])
    aggregate_manifest = {
        "schema_version": _nocturnal().MANIFEST_SCHEMA,
        "lease_id": lease_id,
        "job_id": signed_job["job_id"],
        "participant_node_id": master_id,
        "subtasks": [
            {
                "subtask_id": result["subtask_id"],
                "result_sha256": hashlib.sha256(
                    (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
                ).hexdigest(),
                "answered": True,
            }
            for result in sorted(collected, key=lambda item: item["subtask_id"])
        ],
        "model": str(collected[0].get("model") if collected else ""),
        "corpus_digest": None,
        "started_at": min((result["started_at"] for result in collected), default=_now_iso(now)),
        "ended_at": max((result["ended_at"] for result in collected), default=_now_iso(now)),
        "coverage": reduced["coverage"],
        "created_at": _now_iso(now),
    }
    if not aggregate_manifest["model"]:
        raise SchedulerError("result_model_missing")
    git_dir = Path(os.environ.get("SPARKNET_NOCTURNAL_GIT_DIR") or (state_dir / "nocturnal.git"))
    _ensure_nocturnal_git(ROLE_ROOT, git_dir)
    artifact = _nocturnal().write_aggregate(
        ROLE_ROOT,
        lease_id,
        signed_job["job_id"],
        reduced,
        aggregate_manifest,
        git_dir=git_dir,
    )
    _emit(
        {
            "ok": True,
            "lease_id": lease_id,
            "job_id": signed_job["job_id"],
            "coverage": reduced["coverage"],
            "artifact": artifact,
        }
    )
    return 0


def _plan(args: argparse.Namespace, now: datetime) -> int:
    state_dir = Path(args.state_dir)
    state = load_state(state_dir)
    if state["state"] == "ARMED":
        lease = state.get("lease")
        expires = parse_ts(lease.get("expires_at")) if isinstance(lease, dict) else None
        if expires is not None and now >= expires:
            _close_lease(state, now, "lease_expired")
            append_event(
                state_dir,
                action="lease_expired",
                state=state["state"],
                now=now,
                lease_id=lease.get("lease_id") if isinstance(lease, dict) else None,
            )

    if state["state"] == "PROBING" and isinstance(state.get("plan"), dict):
        expires = parse_ts(state["plan"].get("expires_at"))
        if expires is not None and now >= expires:
            state["plan"] = None

    inputs = _load_inputs(args, now)
    _append_local(state, now, getattr(args, "interface", None))
    evidence = build_evidence(
        inputs["registry"],
        inputs["rows"],
        inputs["snapshot"],
        state["local_history"],
        now,
        current_boot_id=inputs["boot_id"],
    )
    if state["state"] == "ARMED":
        if not evidence["ready"]:
            _close_lease(state, now, "drained")
            _refusal(state_dir, state, now, evidence["reasons"])
            append_event(
                state_dir,
                action="drain",
                state=state["state"],
                now=now,
                reason=",".join(evidence["reasons"]),
                lease_id=(state.get("lease") or {}).get("lease_id"),
            )
            _emit({"state": state["state"], "ready": False, "reasons": evidence["reasons"]})
            return 2
        _refusal(state_dir, state, now, ["already_armed"])
        _emit({"state": state["state"], "ready": False, "reasons": ["already_armed"]})
        return 2
    if not evidence["ready"]:
        state["state"] = "PROBING"
        state["plan"] = None
        _refusal(state_dir, state, now, evidence["reasons"])
        append_event(
            state_dir,
            action="plan",
            state=state["state"],
            now=now,
            reason=",".join(evidence["reasons"]),
        )
        _emit(
            {
                "state": state["state"],
                "ready": False,
                "reasons": evidence["reasons"],
                "local_samples": len(state["local_history"]),
            }
        )
        return 2
    try:
        lease_start, lease_end = lease_window(now)
    except SchedulerError as exc:
        state["state"] = "DISARMED"
        state["plan"] = None
        _refusal(state_dir, state, now, [str(exc)])
        _emit({"state": state["state"], "ready": False, "reasons": [str(exc)]})
        return 2
    plan = make_plan(evidence, now=now, lease_start=lease_start, lease_end=lease_end)
    state["state"] = "PROBING"
    state["plan"] = plan
    state["lease"] = None
    state["last_reasons"] = []
    save_state(state_dir, state, now)
    append_event(
        state_dir,
        action="plan",
        state=state["state"],
        now=now,
        plan_id=plan["plan_id"],
    )
    _emit({"state": state["state"], "ready": True, "plan": plan})
    return 0


def _arm(args: argparse.Namespace, now: datetime) -> int:
    state_dir = Path(args.state_dir)
    state = load_state(state_dir)
    plan = state.get("plan")
    if state["state"] != "PROBING" or not isinstance(plan, dict):
        raise SchedulerError("no_plan")
    if not args.plan_id or args.plan_id != plan.get("plan_id"):
        raise SchedulerError("plan_id_mismatch")
    if not args.confirm or args.confirm != plan.get("plan_id"):
        raise SchedulerError("confirmation_mismatch")
    expires = parse_ts(plan.get("expires_at"))
    if expires is None or now >= expires:
        raise SchedulerError("plan_expired")
    lease = plan.get("lease")
    if not isinstance(lease, dict):
        raise SchedulerError("plan_malformed")
    lease_start = parse_ts(lease.get("start_at"))
    lease_end = parse_ts(lease.get("expires_at"))
    if lease_start is None or lease_end is None or now >= lease_end:
        raise SchedulerError("lease_window_closed")
    if not args.reason or not args.reason.strip():
        raise SchedulerError("reason_required")
    # Arming should use a sample taken now, not one up to ten minutes old from
    # the plan, but never one that crowds the previous sample. Persist it even
    # when the arm is refused, so the operator can see why.
    _append_local_if_due(state, now, getattr(args, "interface", None))
    save_state(state_dir, state, now)
    inputs = _load_inputs(args, now)
    evidence = build_evidence(
        inputs["registry"],
        inputs["rows"],
        inputs["snapshot"],
        state["local_history"],
        now,
        current_boot_id=inputs["boot_id"],
    )
    if not evidence["ready"]:
        _refusal(state_dir, state, now, evidence["reasons"])
        raise SchedulerError(f"not_idle: {', '.join(evidence['reasons'])}")
    if evidence["roster_digest"] != plan.get("roster_digest"):
        raise SchedulerError("roster_changed")
    started = max(now, lease_start)
    active = {
        "lease_id": f"lease-{secrets.token_hex(8)}",
        "plan_id": plan["plan_id"],
        "started_at": _now_iso(started),
        "expires_at": _now_iso(lease_end),
        "operator": _operator(args.operator),
        "reason": args.reason.strip(),
        "roster_digest": evidence["roster_digest"],
        "evidence_digest": evidence["evidence_digest"],
        "assignments": list(plan.get("assignments") or []),
    }
    state["state"] = "ARMED"
    state["lease"] = active
    state["last_reasons"] = []
    save_state(state_dir, state, now)
    append_event(
        state_dir,
        action="arm",
        state=state["state"],
        now=now,
        plan_id=plan["plan_id"],
        lease_id=active["lease_id"],
    )
    _emit({"state": state["state"], "lease": active})
    return 0


def _notify_status(payload: dict[str, Any]) -> None:
    """Best-effort operator ping; the probe timer may never arm."""
    try:
        notify = _load_module(REPO_ROOT / "shared" / "sparknet-notify.py", "sparknet_scheduler_notify")
        state = payload.get("state", "unknown")
        reasons = payload.get("reasons") or []
        body = f"nocturnal: state={state} ready={payload.get('ready')} reasons={','.join(reasons) or '-'}"
        notify.notify_kde(body)
    except Exception:
        # A courtesy ping must never turn a read-only status into a failure.
        return


def _status(args: argparse.Namespace, now: datetime) -> int:
    state_dir = Path(args.state_dir)
    state = load_state(state_dir)
    inputs = _load_inputs(args, now)
    evidence = build_evidence(
        inputs["registry"],
        inputs["rows"],
        inputs["snapshot"],
        state["local_history"],
        now,
        current_boot_id=inputs["boot_id"],
    )
    lease = state.get("lease")
    expired = False
    if isinstance(lease, dict):
        expires = parse_ts(lease.get("expires_at"))
        expired = expires is not None and now >= expires
    payload = {
        "state": state["state"],
        "plan": state.get("plan"),
        "lease": lease,
        "lease_expired": expired,
        "ready": evidence["ready"],
        "reasons": evidence["reasons"],
        "local_samples": len(state["local_history"]),
    }
    _emit(payload)
    if getattr(args, "notify", False):
        _notify_status(payload)
    return 0


def _abort(args: argparse.Namespace, now: datetime) -> int:
    state_dir = Path(args.state_dir)
    state = load_state(state_dir)
    reason = (args.reason or "operator_abort").strip()
    lease = state.get("lease")
    previous = state["state"]
    if previous == "ARMED":
        _close_lease(state, now, reason)
    elif previous == "PROBING":
        state["state"] = "DISARMED"
        state["plan"] = None
    elif previous in {"DRAINING", "CLOSED"}:
        state["state"] = "CLOSED"
    else:
        state["state"] = "DISARMED"
        state["plan"] = None
    state["last_reasons"] = [reason]
    save_state(state_dir, state, now)
    append_event(
        state_dir,
        action="abort",
        state=state["state"],
        now=now,
        reason=reason,
        lease_id=lease.get("lease_id") if isinstance(lease, dict) else None,
    )
    _emit({"state": state["state"], "lease": lease, "reason": reason})
    return 0


def _parse_now(value: str | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchedulerError("--now must be ISO-8601") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nocturnal batch-lease scheduler and signed job dispatcher")
    parser.add_argument("--registry", default=str(default_registry()))
    parser.add_argument("--telemetry", default=str(default_spool()))
    parser.add_argument("--snapshot", default=str(default_snapshot()))
    parser.add_argument("--state-dir", default=str(default_state_dir()))
    parser.add_argument("--interface", default=None, help="local WireGuard interface for the Master probe")
    parser.add_argument("--now", default=None, help="fixed ISO timestamp for tests")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan")
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--plan-id", required=True)
    arm_parser.add_argument("--confirm", required=True)
    arm_parser.add_argument("--operator", default=None)
    arm_parser.add_argument("--reason", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--notify", action="store_true", help="best-effort operator ping; never arms")
    abort_parser = subparsers.add_parser("abort")
    abort_parser.add_argument("--reason", default=None)
    dispatch_parser = subparsers.add_parser("dispatch")
    dispatch_parser.add_argument("--job", required=True, help="signed or unsigned cluster-job JSON")
    dispatch_parser.add_argument("--lease-id", default=None)
    dispatch_parser.add_argument("--signer-socket", default=None)
    dispatch_parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args(argv)
    try:
        now = _parse_now(args.now)
        if args.command == "plan":
            return _plan(args, now)
        if args.command == "arm":
            return _arm(args, now)
        if args.command == "status":
            return _status(args, now)
        if args.command == "abort":
            return _abort(args, now)
        if args.command == "dispatch":
            return _dispatch(args, now)
        raise SchedulerError("unknown_command")
    except SchedulerError as exc:
        _emit({"error": str(exc)})
        return 2
    except (OSError, ValueError) as exc:
        print(f"sparknet-scheduler: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
