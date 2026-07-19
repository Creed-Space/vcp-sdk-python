"""``vcp`` command-line interface — Creed Commons plus protocol operations.

Creed Commons:

    vcp search <query> [--registry URL|PATH]
    vcp install <namespace/id[@version]> [--target DIR] [--registry URL|PATH]
    vcp verify [--target DIR]
    vcp namespaces [--registry URL|PATH]
    vcp lint <hub_root>
    vcp build-index <hub_root>
    vcp publish <artifact.md> --hub <hub_root> [--base-entry entry.json]

Protocol operations (see :mod:`vcp.protocol_cli`):

    vcp token validate <token>
    vcp token parse <csm1-code>
    vcp lite validate <file.json>
    vcp lite to-csm1 <file.json>
    vcp encode [--space office --agency peer ...]
    vcp classify "<principle text>"
    vcp status

Artifacts are signed DATA. Nothing this tool installs is ever imported, evaled,
or executed; there are no post-install hooks.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..protocol_cli import ProtocolError
from ..protocol_cli import register as register_protocol_commands
from .errors import HubError
from .install import install, verify_tree
from .lint import lint_hub_tree, write_index
from .publish import publish
from .registry import DEFAULT_REGISTRY_URL, RegistryClient


def _cmd_search(args: argparse.Namespace) -> int:
    client = RegistryClient(args.registry)
    index = client.index()
    query = args.query.lower()
    hits = []
    for ref, record in sorted(index["artifacts"].items()):
        latest = record.get("latest", "")
        meta = record.get("versions", {}).get(latest, {})
        haystack = " ".join(str(x) for x in (ref, meta.get("name"), meta.get("description")) if x).lower()
        if query in haystack:
            hits.append((ref, latest, meta))
    if not hits:
        print(f"no artifacts matching {args.query!r} in {client.location}")
        return 1
    for ref, latest, meta in hits:
        tier = meta.get("trust_tier", "?")
        print(f"{ref}@{latest}  [{tier}]  {meta.get('name', '')}")
        if meta.get("description"):
            print(f"    {meta['description']}")
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    client = RegistryClient(args.registry)
    result = install(args.ref, args.target, client)
    print(f"installed {result.ref}@{result.version}")
    print(f"  sha256:   {result.content_sha256}")
    print(f"  signed by: {result.key_id}")
    if result.trust_tier == "verified":
        print("  trust tier: verified (root counter-signature checked)")
    else:
        print(f"  trust tier: {result.trust_tier} (integrity + origin only; semantics not vouched for)")
    for f in result.files:
        print(f"  wrote {f}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    client = RegistryClient(args.registry) if args.registry else None
    refs = verify_tree(args.target, registry=client)
    for ref in refs:
        print(f"ok {ref}")
    against = "vcp.lock + live signed index" if client else "vcp.lock"
    print(f"verified {len(refs)} artifact(s) against {against}")
    return 0


def _cmd_namespaces(args: argparse.Namespace) -> int:
    client = RegistryClient(args.registry)
    ns_registry = client.namespace_registry()
    for name in sorted(ns_registry.names):
        keys = ", ".join(sorted(ns_registry.publisher_keys(name)))
        print(f"{name}  keys: {keys}")
    print(f"{len(ns_registry.names)} registered namespace(s); registration: GOVERNANCE.md in the vcp-hub repo")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    report = lint_hub_tree(args.hub_root, require_signed_index=not args.pr)
    for label in report.checked:
        print(f"ok {label}")
    for problem in report.problems:
        print(f"FAIL {problem}", file=sys.stderr)
    print(f"{len(report.checked)} passed, {len(report.problems)} failed")
    return 0 if report.ok else 1


def _cmd_build_index(args: argparse.Namespace) -> int:
    report = write_index(args.hub_root)
    print(f"index.json written from {len(report.checked)} entries")
    for problem in report.problems:
        print(f"SKIPPED (lint failure): {problem}", file=sys.stderr)
    return 0 if report.ok else 1


def _cmd_publish(args: argparse.Namespace) -> int:
    base_entry = None
    if args.base_entry:
        try:
            base_entry = json.loads(Path(args.base_entry).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HubError(f"cannot read base entry {args.base_entry}: {exc}") from exc
    ref = publish(args.artifact, args.hub, namespace=args.namespace, base_entry=base_entry)
    print(f"published {ref} into {args.hub} (open a PR to the vcp-hub repo to release)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vcp",
        description="Creed Commons client — install signed value artifacts (data, never code).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("search", help="search the registry index")
    p.add_argument("query")
    p.add_argument("--registry", default=DEFAULT_REGISTRY_URL)
    p.set_defaults(func=_cmd_search)

    p = sub.add_parser("install", help="verify and install an artifact")
    p.add_argument("ref", help="namespace/id[@version]")
    p.add_argument("--target", default="creed_artifacts")
    p.add_argument("--registry", default=DEFAULT_REGISTRY_URL)
    p.set_defaults(func=_cmd_install)

    p = sub.add_parser("verify", help="re-verify installed artifacts against vcp.lock")
    p.add_argument("--target", default="creed_artifacts")
    p.add_argument(
        "--registry",
        default=None,
        help="also re-check every pin against this registry's live signed index",
    )
    p.set_defaults(func=_cmd_verify)

    p = sub.add_parser("namespaces", help="list registered namespaces and their key ids")
    p.add_argument("--registry", default=DEFAULT_REGISTRY_URL)
    p.set_defaults(func=_cmd_namespaces)

    p = sub.add_parser("lint", help="lint a registry tree (the vcp-hub CI check)")
    p.add_argument("hub_root")
    p.add_argument(
        "--pr",
        action="store_true",
        help="PR-preparation mode: skip the signed-index requirement (only the maintainer ceremony can sign)",
    )
    p.set_defaults(func=_cmd_lint)

    p = sub.add_parser("build-index", help="regenerate index.json from lint-passing entries")
    p.add_argument("hub_root")
    p.set_defaults(func=_cmd_build_index)

    p = sub.add_parser("publish", help="publish a signed artifact into a hub tree")
    p.add_argument("artifact")
    p.add_argument("--hub", required=True)
    p.add_argument("--namespace", default="creed-space")
    p.add_argument("--base-entry", default=None, help="existing compiled registry entry to extend")
    p.set_defaults(func=_cmd_publish)

    # Protocol operations (token/lite/encode/classify/status) — same shaping
    # functions the MCP server uses, so CLI and MCP output cannot drift.
    register_protocol_commands(sub)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (HubError, ProtocolError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
