#!/usr/bin/env python3
"""Cluster KillSwitch — root-gated, Master-side containment (Master plan Step 8).

This is deliberately **not** the peer's node-containment switch. Scope differs:

* peer containment (`peer-node/scripts/sparknet-node-containment.sh`) tears down
  *that node's* overlay and local services;
* this switch runs only on the Master, stops the Master's fabric control planes,
  removes the overlay every peer's authority path depends on, and installs an
  emergency firewall policy that drops overlay and control-plane traffic.

It does **not** SSH into peers, and it does not claim to stop their local chat
surfaces. What it removes is the cluster: the authority plane, the signer, the
peer intake, the delivery timer, the admin container and the overlay transport.
A peer left running locally can no longer receive a signed instruction, so it is
inert for guarded actions — the same isolation a revocation produces, applied to
the whole fabric at once.

Destructive by design, so the default is a dry-run. `--force` is required to
change anything. The root gate runs for both modes: a help request is safe, but a
plan of a destructive action is still a root-only operation.

Why the host ruleset is not flushed
-----------------------------------
The historical draft called `nft flush ruleset`. That removes Docker's own
rules and the host firewall at the same moment it tries to contain the host, and
it can strand the operator outside SSH. The deployed Masters use the legacy
iptables toolchain (the fabric's own firewall is iptables), so this implementation
adds three private chains and jumps to them: explicit drops for the overlay
interface, the control-plane ports and the forward hook, with no change to the
host's built-in policies. It is still a containment policy, not a firewall
replacement.

Recovery is a deliberate operator action, not an inverse flag: remove the three
jumps, flush/delete `SPARKNET_EMERG_IN`, `SPARKNET_EMERG_OUT` and
`SPARKNET_EMERG_FWD`, re-enable the units, then bring the overlay anchor back up
(see `docs/killswitch-template.md`).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

#: Master-side services that carry fabric authority or fabric telemetry.
#: Missing units are expected on a staged host; `optional=True` records the
#: failure without pretending the rest of the containment did not happen.
CONTROL_UNITS = (
    "sparknet-master-signer.service",
    "sparknet-peer-intake.service",
    "sparknet-reflex-broker.service",
    "sparknet-registry-deliver.timer",
    "sparknet-registry-deliver.service",
)

#: The overlay anchor is disabled as well: a reboot must not silently restore the
#: authority path the operator just removed.
ANCHOR_UNIT = "sparknet-master-wireguard-anchor.service"

#: The admin surface is the one LLM-driven Master surface. Stop it, and remove its
#: restart policy so a Docker daemon restart cannot resurrect it.
ADMIN_CONTAINER = "sparknet-admin-webui"

#: Ports that carry an authority or fabric-control path on the Master. The
#: overlay is dropped first; these are defence in depth for a stale interface or
#: a service bound to a host address.
CONTROL_TCP_PORTS = (
    8081,  # control-plane gateway
    8088,  # admin surface
    8090,  # peer intake
    4203,  # share ratification (specified)
    4210,  # cluster election
    4220,  # fabric git
    4221,  # file share
    4222,  # NAT administration
    4223,  # vector store
    4224,  # reflex broker
    9090,  # peer guard (the Master runs the peer services by path)
)
WIREGUARD_UDP_PORT = 51820

CHAIN_IN = "SPARKNET_EMERG_IN"
CHAIN_OUT = "SPARKNET_EMERG_OUT"
CHAIN_FWD = "SPARKNET_EMERG_FWD"


@dataclass(frozen=True)
class Action:
    """One ordered step, with the exact argv a test can inspect."""

    summary: str
    argv: tuple[str, ...]
    optional: bool = False
    stdin: str = ""


#: A root command that failed because its target did not exist is not a
#: containment failure: the goal (that target is not running) already holds.
#: Anything else is a real failure and must make the run exit non-zero.
ABSENT_MARKERS = (
    "not found",
    "does not exist",
    "no such file",
    "no such container",
    "cannot find device",
    "not loaded",
    "no chain",
    "bad rule",
    "does a matching rule exist",
)


def is_absent(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in ABSENT_MARKERS)


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)
    performed: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


def control_port_set() -> str:
    """The multiport argument the input chain drops (non-loopback only)."""
    return ",".join(str(port) for port in CONTROL_TCP_PORTS)


def cleanup_actions() -> list[Action]:
    """Remove an earlier containment policy before installing a fresh one.

    The jump has to go first: iptables refuses to flush or delete a chain that is
    still referenced. Each step is optional because a first run has nothing to
    remove; a real failure (permission, corrupt ruleset) is still reported.
    """
    actions: list[Action] = []
    for hook, chain in (("INPUT", CHAIN_IN), ("OUTPUT", CHAIN_OUT), ("FORWARD", CHAIN_FWD)):
        actions.append(
            Action(
                f"remove the {chain} jump from {hook}",
                ("iptables", "-D", hook, "-j", chain),
                optional=True,
            )
        )
        actions.append(Action(f"flush {chain}", ("iptables", "-F", chain), optional=True))
        actions.append(Action(f"delete {chain}", ("iptables", "-X", chain), optional=True))
    return actions


def install_actions(interface: str) -> list[Action]:
    """Build the private chains, then jump to them from each built-in hook.

    The rules are appended before the jump is inserted, so a half-built chain is
    never reachable. No `flush` and no built-in policy change: the host's own
    firewall and Docker rules survive, and an operator's SSH session is input/lo
    and therefore outside the control-port drops.
    """
    ports = control_port_set()
    return [
        Action(f"create {CHAIN_IN}", ("iptables", "-N", CHAIN_IN)),
        Action(
            f"drop traffic arriving on {interface}",
            ("iptables", "-A", CHAIN_IN, "-i", interface, "-j", "DROP"),
        ),
        Action(
            "drop non-loopback control-plane TCP",
            (
                "iptables",
                "-A",
                CHAIN_IN,
                "!",
                "-i",
                "lo",
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                ports,
                "-j",
                "DROP",
            ),
        ),
        Action(
            "drop non-loopback WireGuard UDP",
            (
                "iptables",
                "-A",
                CHAIN_IN,
                "!",
                "-i",
                "lo",
                "-p",
                "udp",
                "--dport",
                str(WIREGUARD_UDP_PORT),
                "-j",
                "DROP",
            ),
        ),
        Action(
            f"insert the {CHAIN_IN} jump",
            ("iptables", "-I", "INPUT", "1", "-j", CHAIN_IN),
        ),
        Action(f"create {CHAIN_OUT}", ("iptables", "-N", CHAIN_OUT)),
        Action(
            f"drop traffic leaving on {interface}",
            ("iptables", "-A", CHAIN_OUT, "-o", interface, "-j", "DROP"),
        ),
        Action(
            f"insert the {CHAIN_OUT} jump",
            ("iptables", "-I", "OUTPUT", "1", "-j", CHAIN_OUT),
        ),
        Action(f"create {CHAIN_FWD}", ("iptables", "-N", CHAIN_FWD)),
        Action("drop all forwarded traffic", ("iptables", "-A", CHAIN_FWD, "-j", "DROP")),
        Action(
            f"insert the {CHAIN_FWD} jump",
            ("iptables", "-I", "FORWARD", "1", "-j", CHAIN_FWD),
        ),
    ]


def build_actions(interface: str) -> list[Action]:
    """The ordered containment sequence, pure and testable."""
    actions = [
        Action(
            f"stop and disable {unit}",
            ("systemctl", "disable", "--now", unit),
            optional=True,
        )
        for unit in CONTROL_UNITS
    ]
    actions.extend(
        [
            Action(
                f"stop and disable {ANCHOR_UNIT}",
                ("systemctl", "disable", "--now", ANCHOR_UNIT),
                optional=True,
            ),
            Action(
                f"remove the restart policy from {ADMIN_CONTAINER}",
                ("docker", "update", "--restart=no", ADMIN_CONTAINER),
                optional=True,
            ),
            Action(
                f"stop {ADMIN_CONTAINER}",
                ("docker", "stop", ADMIN_CONTAINER),
                optional=True,
            ),
            Action(
                f"delete the overlay interface {interface}",
                ("ip", "link", "del", interface),
                optional=True,
            ),
        ]
    )
    actions.extend(cleanup_actions())
    actions.extend(install_actions(interface))
    return actions


def run_action(action: Action) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        action.argv,
        input=action.stdin or None,
        capture_output=True,
        text=True,
        check=False,
    )


def execute(
    actions: Sequence[Action],
    *,
    runner: Callable[[Action], subprocess.CompletedProcess[str]] = run_action,
    out=print,
) -> Report:
    """Run the sequence in order. Containment does not stop on the first failure.

    A missing signer unit must not prevent the overlay from coming down, and a
    failed Docker stop must not prevent the firewall policy. Failures are collected
    and reported at the end, so the operator sees the whole state rather than
    only the first missing service.
    """
    report = Report()
    for action in actions:
        out(f"[killswitch] {action.summary}")
        result = runner(action)
        detail = (result.stdout or "").strip()
        if detail:
            out(f"  {detail}")
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "").strip()
            detail = message or f"exit {result.returncode}"
            if action.optional and is_absent(detail):
                out(f"  (absent: {detail})")
                report.absent.append(action.summary)
                continue
            report.failures.append(f"{action.summary}: {detail}")
        else:
            report.performed.append(action.summary)
    return report


def _interface() -> str:
    """Refuse to guess the overlay interface, exactly as the anchor does."""
    interface = os.environ.get("SPARKNET_WG_INTERFACE", "").strip()
    if not interface:
        raise ValueError("SPARKNET_WG_INTERFACE is not set — refusing to guess which interface to tear down")
    return interface


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Master-side cluster KillSwitch. Stops the fabric control planes, "
            "removes the overlay and installs an emergency iptables drop policy. "
            "Not the peer's node-containment switch."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="print the plan and change nothing (default)")
    mode.add_argument("--force", action="store_true", help="perform the destructive containment")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print("killswitch: root required (EUID 0); nothing was changed", file=sys.stderr)
        return 1

    try:
        interface = _interface()
    except ValueError as exc:
        print(f"killswitch: {exc}; nothing was changed", file=sys.stderr)
        return 1

    actions = build_actions(interface)
    if not args.force:
        print(f"killswitch: DRY-RUN (interface {interface}); pass --force to execute")
        for action in actions:
            print(f"  - {action.summary}")
        return 0

    print(f"killswitch: ENGAGING cluster containment on {interface}")
    report = execute(actions)
    if not report.ok:
        print("killswitch: containment incomplete:", file=sys.stderr)
        for failure in report.failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("killswitch: control planes halted, overlay removed, emergency drop installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
