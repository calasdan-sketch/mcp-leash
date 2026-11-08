"""A JSON Schema for policy files (`mcp-leash schema`), for editor
autocomplete and CI linting. It is generated from the same tables the policy
loader uses (the key list, the scan detectors and actions), and a test keeps
the two from drifting. The schema describes the *shape*; the loader remains
the authority (regexes, duplicate tool names after normalising, and the like
are checked only there: run `mcp-leash check`)."""

from __future__ import annotations

from . import jail
from . import scan

SCHEMA_URL = "https://json-schema.org/draft/2020-12/schema"


def _names(desc: str) -> dict:
    return {"type": "array", "items": {"type": "string", "minLength": 1},
            "description": desc}


_RULE = {"oneOf": [
    {"type": "string", "description": "a regular expression"},
    {"type": "object", "additionalProperties": False, "minProperties": 1,
     "properties": {"type": {"enum": list(jail.VALUE_TYPES)},
                    "pattern": {"type": "string"}}},
]}
_RULES = {"oneOf": [
    _RULE,
    {"type": "array", "items": _RULE},
    {"type": "object", "additionalProperties": {"oneOf": [
        _RULE, {"type": "array", "items": _RULE}]}},
]}


def _scan_schema() -> dict:
    props: dict = {"_comment": {"type": "string"},
                   "decode": {"type": "boolean"}}
    for section, (kinds, actions) in scan.SECTIONS.items():
        props[section] = {
            "type": "object", "additionalProperties": False,
            "properties": {k: {"enum": list(actions)} for k in kinds}}
    return {"type": "object", "additionalProperties": False, "properties": props}


def _limits_schema() -> dict:
    count = {"type": "integer", "minimum": 1}
    tool = {"type": "object", "additionalProperties": False,
            "properties": {k: count for k in jail._TOOL_LIMIT_KEYS}}
    props = {k: count for k in jail._LIMIT_NUMBERS}
    props["max_message_bytes"] = {"type": "integer",
                                  "minimum": jail.MIN_MESSAGE_CAP}
    props["per_tool"] = {"type": "object", "additionalProperties": tool}
    props["_comment"] = {"type": "string"}
    return {"type": "object", "additionalProperties": False, "properties": props}


def policy_schema() -> dict:
    props = {
        "allow_tools": _names("tools that may be called; \"*\" is every tool"),
        "deny_tools": _names("tools that may never be called (wins over "
                             "allow_tools); \"*\" is every tool"),
        "arg_rules": {"type": "object", "additionalProperties": {
            "type": "object", "additionalProperties": False,
            "properties": {"allow": {"anyOf": [{"const": "*"}, _RULES]},
                           "deny": _RULES}}},
        "policed_methods": _names("methods checked like tools/call"),
        "deny_methods": _names("methods refused outright; \"resources/*\" "
                               "style patterns are allowed here"),
        "strict_args": {"type": "boolean"},
        "audit_args": {"enum": list(jail.AUDIT_ARGS_MODES)},
        "hide_denied": {"type": "boolean"},
        "tool_pins": {"type": "object", "additionalProperties": {
            "type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}},
        "require_pins": {"type": "boolean"},
        "scan": _scan_schema(),
        "limits": _limits_schema(),
        "audit_redact": {"type": "boolean"},
        "audit_max_bytes": {"type": "integer", "minimum": 4096},
        "audit_required": {"type": "boolean"},
    }
    for note in jail.NOTE_KEYS:
        props[note] = {}
    assert set(props) == set(jail.POLICY_KEYS) | set(jail.NOTE_KEYS)
    return {"$schema": SCHEMA_URL,
            "title": "mcp-leash policy",
            "description": "Shape of an mcp-leash policy file. `mcp-leash "
                           "check --policy FILE` is the full validation.",
            "type": "object", "additionalProperties": False,
            "properties": props}
