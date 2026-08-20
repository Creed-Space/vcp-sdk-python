"""Protocol subcommands for the ``vcp`` CLI — token, lite, encode, classify.

These mirror the MCP tools one-for-one and call the same shaping functions in
:mod:`vcp._ops`, so a scripted CLI run and an MCP tool call return the same
fields.

Output is JSON on stdout by default. ``--quiet`` prints the single value the
command is really about (a canonical token, a CSM1 code, a wire string), so a
shell can consume it without a JSON parser. Commands that answer a yes/no
question exit 0 when valid and 1 when invalid, which is what makes them usable
in a pipeline or a CI gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import _ops
from ._json import loads_strict
from .context import PERSONAL_DIMENSIONS, SITUATIONAL_DIMENSIONS

#: Dimensions that accept several values (repeat the flag).
_MULTI = frozenset(_ops.MULTI_VALUE_DIMENSIONS)
MAX_JSON_DOCUMENT_BYTES = 8 * 1024 * 1024


class ProtocolError(Exception):
    """A CLI-level input problem (unreadable file, malformed JSON)."""


def _emit(payload: dict[str, Any], quiet_key: str | None, args: argparse.Namespace) -> None:
    """Print the payload as JSON, or just the interesting value under --quiet."""
    if getattr(args, "quiet", False) and quiet_key and quiet_key in payload:
        print(payload[quiet_key])
        return
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _read_json_document(path: str) -> dict[str, Any]:
    try:
        source = Path(path)
        if source.stat().st_size > MAX_JSON_DOCUMENT_BYTES:
            raise ProtocolError(f"cannot read {path}: document exceeds {MAX_JSON_DOCUMENT_BYTES} byte size cap")
        with source.open("rb") as handle:
            raw_bytes = handle.read(MAX_JSON_DOCUMENT_BYTES + 1)
        if len(raw_bytes) > MAX_JSON_DOCUMENT_BYTES:
            raise ProtocolError(f"cannot read {path}: document exceeds {MAX_JSON_DOCUMENT_BYTES} byte size cap")
        raw = raw_bytes.decode("utf-8")
    except ProtocolError:
        raise
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"{path} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ProtocolError(f"cannot read {path}: {exc}") from exc
    try:
        document = loads_strict(raw)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ProtocolError(f"{path} must contain a JSON object, got {type(document).__name__}")
    return document


# === Commands ===


def _cmd_token_validate(args: argparse.Namespace) -> int:
    result = _ops.validate_token(args.token)
    _emit(result, "canonical", args)
    return 0 if result["valid"] else 1


def _cmd_token_parse(args: argparse.Namespace) -> int:
    result = _ops.parse_csm1(args.code)
    _emit(result, "canonical", args)
    return 0 if result["valid"] else 1


def _cmd_lite_validate(args: argparse.Namespace) -> int:
    result = _ops.validate_lite(_read_json_document(args.document))
    _emit(result, "csm1_code", args)
    return 0 if result["valid"] else 1


def _cmd_lite_to_csm1(args: argparse.Namespace) -> int:
    document = _read_json_document(args.document)
    # Validate first: converting an invalid document would report a CSM1 code
    # for a profile the schema rejects, which is worse than a clear failure.
    validation = _ops.validate_lite(document)
    if not validation["valid"]:
        print(json.dumps(validation, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1

    result = _ops.lite_to_csm1(
        persona=document["persona"],
        adherence=document["adherence"],
        scopes=document["scopes"],
        namespace=document.get("namespace"),
    )
    if "error" in result:
        print(json.dumps(result, indent=2, ensure_ascii=False), file=sys.stderr)
        return 1
    _emit(result, "csm1_code", args)
    return 0


def _cmd_encode(args: argparse.Namespace) -> int:
    dimensions = {
        dim: getattr(args, dim)
        for dim in (*SITUATIONAL_DIMENSIONS, *PERSONAL_DIMENSIONS)
        if getattr(args, dim, None) is not None
    }
    for dim in PERSONAL_DIMENSIONS:
        intensity = getattr(args, f"{dim}_intensity", None)
        if intensity is not None:
            dimensions[f"{dim}_intensity"] = intensity

    try:
        result = _ops.encode_context(**dimensions)
    except ValueError as exc:
        raise ProtocolError(str(exc)) from exc
    _emit(result, "wire_format", args)
    return 0


def _cmd_classify(args: argparse.Namespace) -> int:
    result = _ops.classify_principle_op(
        args.principle,
        principle_type=args.type,
        existing_values=args.existing or None,
    )
    _emit(result, "schwartz_value", args)
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    _emit(_ops.status(), "sdk_version", args)
    return 0


# === Parser wiring ===


def _add_quiet(parser: argparse.ArgumentParser, what: str) -> None:
    parser.add_argument("--quiet", "-q", action="store_true", help=f"print only the {what}")


def register(sub: argparse._SubParsersAction) -> None:
    """Attach the protocol subcommands to an existing ``vcp`` subparser set."""
    # --- vcp token ---
    token = sub.add_parser("token", help="VCP/I tokens and CSM1 codes")
    token_sub = token.add_subparsers(dest="token_command", required=True)

    p = token_sub.add_parser("validate", help="validate a VCP/I identity token (exit 0 valid, 1 invalid)")
    p.add_argument("token")
    _add_quiet(p, "canonical token")
    p.set_defaults(func=_cmd_token_validate)

    p = token_sub.add_parser("parse", help="parse a CSM1 code (exit 0 valid, 1 invalid)")
    p.add_argument("code", help="CSM1 code, e.g. N5+F+E")
    _add_quiet(p, "canonical code")
    p.set_defaults(func=_cmd_token_parse)

    # --- vcp lite ---
    lite = sub.add_parser("lite", help="VCP-Lite documents")
    lite_sub = lite.add_subparsers(dest="lite_command", required=True)

    p = lite_sub.add_parser("validate", help="validate a VCP-Lite document (exit 0 valid, 1 invalid)")
    p.add_argument("document", help="path to a VCP-Lite JSON file")
    _add_quiet(p, "CSM1 code")
    p.set_defaults(func=_cmd_lite_validate)

    p = lite_sub.add_parser("to-csm1", help="convert a VCP-Lite document to its CSM1 code")
    p.add_argument("document", help="path to a VCP-Lite JSON file")
    _add_quiet(p, "CSM1 code")
    p.set_defaults(func=_cmd_lite_to_csm1)

    # --- vcp encode ---
    encode = sub.add_parser(
        "encode",
        help="encode context dimensions to the VCP/A wire format",
        description=(
            "Encode contextual state to the VCP/A wire format. Pass one flag per "
            "dimension; repeat --company/--constraints for multiple values."
        ),
    )
    for dim in SITUATIONAL_DIMENSIONS:
        flag = f"--{dim.replace('_', '-')}"
        if dim in _MULTI:
            encode.add_argument(flag, dest=dim, action="append", help=f"{dim} (repeatable)")
        else:
            encode.add_argument(flag, dest=dim, help=dim)
    for dim in PERSONAL_DIMENSIONS:
        flag = f"--{dim.replace('_', '-')}"
        encode.add_argument(flag, dest=dim, help=dim)
        encode.add_argument(
            f"{flag}-intensity",
            dest=f"{dim}_intensity",
            type=int,
            help=f"{dim} intensity 1-5",
        )
    _add_quiet(encode, "wire format string")
    encode.set_defaults(func=_cmd_encode)

    # --- vcp classify ---
    p = sub.add_parser("classify", help="map a constitution principle to a Schwartz value")
    p.add_argument("principle", help="principle text, e.g. 'Never endanger a child'")
    p.add_argument("--type", default="never", help="principle type (default: never)")
    p.add_argument(
        "--existing",
        action="append",
        help="an existing Schwartz value to check for tension (repeatable)",
    )
    _add_quiet(p, "Schwartz value")
    p.set_defaults(func=_cmd_classify)

    # --- vcp status ---
    p = sub.add_parser("status", help="SDK and spec versions, capabilities, vocabularies")
    _add_quiet(p, "SDK version")
    p.set_defaults(func=_cmd_status)
