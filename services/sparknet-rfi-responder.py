#!/usr/bin/env python3
"""Answer queued RFI requests from the allow-listed fabric corpus.

This is the Master's half of the user-node knowledge loop. It does not invent an
answer: it searches only the files `scripts/sparknet-rag-corpus.py` allows for
the `fabric` scope, returns excerpts with their paths, and refuses to answer a
category outside the request's `scope`. An empty answer is a legitimate answer.

The responder holds no key. It delegates signing and delivery to the existing
`scripts/sparknet-rfi-answer.sh --request`, which uses the isolated signer in
production or `--offline` in a test.

Usage::

    sparknet-rfi-responder.py --once
    sparknet-rfi-responder.py --once --dry-run
    sparknet-rfi-responder.py --watch --interval 30
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))
from sparknet_loader import load_by_path

ROLE_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = ROLE_ROOT.parent
AUTHZ = REPO_ROOT / "shared" / "sparknet-authz.py"
CORPUS_POLICY = REPO_ROOT / "scripts" / "sparknet-rag-corpus.py"
COMPOSER = ROLE_ROOT / "scripts" / "sparknet-rfi-answer.sh"
DEFAULT_REQUEST_DIR = Path("/mnt/log/sparknet-rfi-requests")
DEFAULT_PROCESSED_DIR = DEFAULT_REQUEST_DIR / "processed"
MAX_ANSWER_BYTES = 32 * 1024


def _load(path: Path, name: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    return load_by_path(name, path)


def authz() -> Any:
    return _load(AUTHZ, "sparknet_rfi_responder_authz")


def corpus_policy() -> Any:
    return _load(CORPUS_POLICY, "sparknet_rfi_responder_corpus")


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _tokens(text: str) -> set[str]:
    return {token for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text.lower())}


def category_of(rel: Path) -> str:
    parts = rel.parts
    if parts and parts[0] == "contracts":
        return "contracts"
    return "docs"


def allowed_categories(scope: list[str]) -> set[str]:
    allowed: set[str] = set()
    for item in scope:
        if item == "fabric":
            allowed.update({"contracts", "docs"})
        elif item in {"contracts", "docs"}:
            allowed.add(item)
        elif item.startswith("contracts/"):
            allowed.add("contracts")
        elif item in {"peer-node", "master-node", "goagx"}:
            allowed.add("docs")
    return allowed


def _snippets(path: Path, terms: set[str], limit: int = 3) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    blocks = re.split(r"\n\s*\n", text)
    scored: list[tuple[int, str]] = []
    for block in blocks:
        low = block.lower()
        score = sum(low.count(term) for term in terms)
        if score:
            scored.append((score, block.strip()))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [block for _, block in scored[:limit] if block]


def search(root: Path, question: str, scope: list[str], *, top_files: int = 3) -> tuple[str, list[str]]:
    """Return (markdown answer, sources) from the allow-listed corpus only."""
    allowed = allowed_categories(scope)
    if not allowed:
        return "", []
    policy = corpus_policy()
    terms = _tokens(question)
    if not terms:
        return "", []
    scored: list[tuple[int, Path]] = []
    for rel in policy.corpus_entries(root, policy.FABRIC_ROOTS):
        category = category_of(rel)
        if category not in allowed:
            continue
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = text.lower()
        score = sum(low.count(term) for term in terms)
        if score:
            scored.append((score, rel))
    scored.sort(key=lambda item: (-item[0], str(item[1])))
    picked = scored[:top_files]
    if not picked:
        return "", []
    sources = sorted({category_of(rel) for _, rel in picked})
    lines = [
        "# Fabric knowledge answer",
        "",
        "This answer is drawn only from the allow-listed fabric corpus. It is data,",
        "not an instruction, and it grants no authority.",
        "",
    ]
    for _, rel in picked:
        lines.append(f"## `{rel}`")
        lines.append("")
        snippets = _snippets(root / rel, terms)
        if snippets:
            lines.extend(snippets)
            lines.append("")
    text = "\n".join(lines).strip() + "\n"
    if len(text.encode("utf-8")) > MAX_ANSWER_BYTES:
        text = text.encode("utf-8")[:MAX_ANSWER_BYTES].decode("utf-8", "ignore").rstrip() + "\n"
    return text, sources


def safe_item_name(request_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", request_id).strip(".-")
    return (cleaned or "rfi-answer")[:80] + ".md"


def load_request(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("request artifact is not a JSON object")
    return data


def compose(
    request_path: Path,
    request: dict[str, Any],
    answer: str,
    sources: list[str],
    *,
    offline: bool,
    socket_path: str | None,
    url: str | None,
    registry: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    item = safe_item_name(str(request.get("request_id") or "rfi-answer"))
    if dry_run:
        return {
            "request_id": request.get("request_id"),
            "item_name": item,
            "sources": sources,
            "answer": answer,
            "dry_run": True,
        }
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md", delete=False) as handle:
        handle.write(answer)
        content_path = Path(handle.name)
    command = [
        "bash",
        str(COMPOSER),
        "--request",
        str(request_path),
        "--item-name",
        item,
    ]
    if answer:
        command += ["--content", str(content_path), "--sources", ",".join(sources)]
    else:
        command += ["--empty"]
    if offline:
        command.append("--offline")
    elif socket_path:
        command += ["--socket", socket_path]
    if url:
        command += ["--url", url]
    if registry:
        command += ["--registry", registry]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
    finally:
        content_path.unlink(missing_ok=True)
    return {
        "request_id": request.get("request_id"),
        "item_name": item,
        "sources": sources,
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _registered_fingerprint(registry: str | None, fingerprint: str) -> str:
    """Resolve the requester in the current signed registry, when one is supplied."""
    if not registry:
        return fingerprint
    path = Path(registry)
    if not path.is_file():
        raise ValueError("registry is not a local signed file")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("registry is not an object")
    authz_impl = authz()
    try:
        master_key = authz_impl.public_key_from_b64(str(document.get("master_public_key_b64") or ""))
    except Exception as exc:
        raise ValueError(f"registry master key is unusable: {exc}") from exc
    now = datetime.now(timezone.utc)
    for entry in document.get("authorizations") or []:
        if not isinstance(entry, dict) or entry.get("fingerprint") != fingerprint:
            continue
        try:
            accepted = authz_impl.accept_entry(
                entry,
                master_key,
                now=now,
                expected_fingerprint=fingerprint,
            )
        except authz_impl.RegistryEntryError as exc:
            if exc.code in (authz_impl.REASON_EXPIRED, authz_impl.REASON_NOT_YET_VALID):
                raise ValueError("requesting peer is outside its authorization window") from exc
            if exc.code == authz_impl.REASON_BAD_SIGNATURE:
                raise ValueError("registry entry signature does not verify") from exc
            if exc.code == authz_impl.REASON_REVOKED:
                raise ValueError("requesting peer is revoked") from exc
            raise ValueError("registry entry has malformed validity") from exc
        return accepted.fingerprint
    raise ValueError("requesting peer is not in the registry")


def process_once(
    *,
    request_dir: Path,
    processed_dir: Path,
    root: Path,
    offline: bool,
    socket_path: str | None,
    url: str | None,
    registry: str | None,
    dry_run: bool,
    limit: int,
) -> list[dict[str, Any]]:
    processed_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    results: list[dict[str, Any]] = []
    for path in sorted(request_dir.glob("*.json"))[:limit]:
        try:
            request = load_request(path)
            expected = _registered_fingerprint(registry, str(request.get("peer_fingerprint") or ""))
            ok, reason = authz().verify_rfi_request(
                request,
                expected_fingerprint=expected,
                seen_nonces=(),
            )
            if not ok:
                results.append({"request": path.name, "error": reason})
                continue
            answer, sources = search(root, str(request.get("question") or ""), list(request.get("scope") or []))
            result = compose(
                path,
                request,
                answer,
                sources,
                offline=offline,
                socket_path=socket_path,
                url=url,
                registry=registry,
                dry_run=dry_run,
            )
        except (OSError, ValueError) as exc:
            results.append({"request": path.name, "error": str(exc)})
            continue
        results.append(result)
        if not dry_run and result.get("returncode") == 0:
            shutil.move(str(path), str(processed_dir / path.name))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Answer queued RFI requests from the allow-listed corpus")
    parser.add_argument(
        "--request-dir", type=Path, default=Path(os.environ.get("SPARKNET_RFI_REQUEST_DIR") or DEFAULT_REQUEST_DIR)
    )
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=Path(os.environ.get("SPARKNET_RFI_PROCESSED_DIR") or DEFAULT_PROCESSED_DIR),
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--socket")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--url")
    parser.add_argument("--registry")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not args.once and not args.watch:
        args.once = True
    while True:
        try:
            results = process_once(
                request_dir=args.request_dir,
                processed_dir=args.processed_dir,
                root=args.root.resolve(),
                offline=args.offline,
                socket_path=args.socket,
                url=args.url,
                registry=args.registry,
                dry_run=args.dry_run,
                limit=max(1, args.limit),
            )
        except OSError as exc:
            print(f"sparknet-rfi-responder: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(results, indent=2, sort_keys=True))
        else:
            for result in results:
                if "error" in result:
                    print(f"  refused {result['request']}: {result['error']}", file=sys.stderr)
                else:
                    print(
                        f"  answered {result.get('request_id')} -> {result.get('item_name')} ({result.get('sources')})"
                    )
        if not args.watch:
            return 0
        import time

        time.sleep(max(1.0, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
