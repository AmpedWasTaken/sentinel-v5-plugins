"""Sentinel V5 one-shot Python plugin SDK (Python 3.10+, stdlib only).

The host authenticates and authorizes commands before invoking a trusted plugin.
Plugins read one bounded JSON request from stdin, write exactly one JSON
response to stdout, and exit. Never print diagnostics to stdout.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, TextIO

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")


@dataclass(frozen=True)
class Request:
    command: str
    actor: str
    role: str
    args: dict[str, str]


@dataclass
class Result:
    text: str = ""
    view: str = ""
    values: dict[str, str] = field(default_factory=dict)


Handler = Callable[[Request], Result | Mapping[str, Any]]


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-standard JSON value")


def _request_from_json(raw: bytes) -> Request:
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("invalid plugin request size")
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid plugin request JSON") from exc
    if not isinstance(payload, dict) or type(payload.get("version")) is not int or payload["version"] != PROTOCOL_VERSION:
        raise ValueError("unsupported plugin protocol")
    command, actor, role, args = (payload.get(k) for k in ("command", "actor", "role", "args"))
    if not isinstance(command, str) or not _NAME.fullmatch(command):
        raise ValueError("invalid plugin command")
    if not isinstance(actor, str) or not actor or not isinstance(role, str) or role not in ("admin", "operator", "viewer"):
        raise ValueError("invalid authenticated plugin context")
    if not isinstance(args, dict) or len(args) > 12:
        raise ValueError("invalid plugin arguments")
    for key, value in args.items():
        if not isinstance(key, str) or not _NAME.fullmatch(key) or not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("invalid plugin argument")
    return Request(command=command, actor=actor, role=role, args=args)


def _safe_error(error: Exception) -> str:
    text = str(error)
    clean = "".join(ch for ch in text if ord(ch) >= 32 and ord(ch) != 127)
    return clean[:180] or "plugin handler failed"


def _normalize_result(value: Result | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Result):
        result = {"text": value.text, "view": value.view, "values": value.values}
    elif isinstance(value, Mapping):
        result = dict(value)
    else:
        raise ValueError("plugin handler must return Result or mapping")
    if set(result) - {"text", "view", "values"}:
        raise ValueError("unknown plugin result field")
    text, view, values = (result.get("text", ""), result.get("view", ""), result.get("values", {}))
    if not isinstance(text, str) or len(text.encode("utf-8")) > 8192:
        raise ValueError("plugin result text too large")
    if not isinstance(view, str) or (view and not _NAME.fullmatch(view)):
        raise ValueError("invalid plugin SML view")
    if not isinstance(values, dict) or len(values) > 24:
        raise ValueError("too many plugin result bindings")
    for key, item in values.items():
        if not isinstance(key, str) or not _NAME.fullmatch(key) or not isinstance(item, str) or len(item.encode("utf-8")) > 4096:
            raise ValueError("invalid plugin result binding")
    return {"text": text, "view": view, "values": values}


class Plugin:
    """Register named handlers declared in plugin.yaml and serve one invocation."""

    def __init__(self) -> None:
        self._commands: dict[str, Handler] = {}

    def command(self, name: str, handler: Handler | None = None):
        if handler is None:
            def decorator(fn: Handler) -> Handler:
                self.command(name, fn)
                return fn
            return decorator
        if not isinstance(name, str) or not _NAME.fullmatch(name) or not callable(handler):
            raise ValueError("invalid plugin command registration")
        if name in self._commands:
            raise ValueError("duplicate plugin command")
        self._commands[name] = handler
        return handler

    def handle(self, raw: bytes) -> dict[str, Any]:
        try:
            request = _request_from_json(raw)
            handler = self._commands.get(request.command)
            if handler is None:
                raise ValueError("unknown plugin command")
            result = _normalize_result(handler(request))
            return {"version": PROTOCOL_VERSION, "result": result}
        except Exception as exc:
            return {"version": PROTOCOL_VERSION, "result": {}, "error": _safe_error(exc)}

    def serve_io(self, source, target: TextIO) -> None:
        raw = source.read(MAX_REQUEST_BYTES + 1)
        reply = self.handle(raw)
        data = json.dumps(reply, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(data.encode("utf-8")) > MAX_RESPONSE_BYTES:
            data = json.dumps({"version": PROTOCOL_VERSION, "result": {}, "error": "plugin response too large"})
        target.write(data + "\n")
        target.flush()

    def serve(self) -> None:
        self.serve_io(sys.stdin.buffer, sys.stdout)
