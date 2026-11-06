"""Pull declared field names out of schemas.

Each parser yields :class:`Field` records: a container (table, model, schema
path), the field name and the 1-based line it was declared on. They are
deliberately shallow: regexes for SQL and Prisma, a tree walk for OpenAPI and
JSON Schema. They do not need to understand types to know that a column called
``aadhaar_no`` exists.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class Field:
    container: str
    name: str
    line: int  # 0 when unknown

    @property
    def locator(self) -> str:
        return f"{self.container}.{self.name}" if self.container else self.name


# ---- SQL DDL ----------------------------------------------------------------

_CREATE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+)?(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?P<name>[\w.\"`\[\]]+)\s*\(",
    re.IGNORECASE,
)
_ALTER_ADD = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?(?P<table>[\w.\"`\[\]]+)\s+ADD\s+(?:COLUMN\s+)?"
    r"(?:IF\s+NOT\s+EXISTS\s+)?(?P<col>[\w\"`\[\]]+)",
    re.IGNORECASE,
)
_CONSTRAINT_WORDS = frozenset(
    {
        "primary",
        "unique",
        "constraint",
        "foreign",
        "check",
        "key",
        "index",
        "exclude",
        "like",
        "partition",
        "with",
        "inherits",
        "references",
    }
)


def _unquote(ident: str) -> str:
    return ident.strip().strip('"`[]')


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_str: str | None = None
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "-" and text.startswith("--", i):
            nl = text.find("\n", i)
            i = len(text) if nl == -1 else nl
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text)


def _split_top_level(body: str) -> Iterator[tuple[str, int]]:
    """Yield (segment, offset) for each comma-separated top-level item."""
    depth = 0
    start = 0
    in_str: str | None = None
    i = 0
    while i < len(body):
        ch = body[i]
        if in_str:
            if ch == in_str:
                in_str = None
        elif ch in ("'", '"'):
            in_str = ch
        elif ch == "-" and body.startswith("--", i):
            nl = body.find("\n", i)
            i = len(body) if nl == -1 else nl
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            yield body[start:i], start
            start = i + 1
        i += 1
    yield body[start:], start


def parse_sql(text: str) -> list[Field]:
    fields: list[Field] = []
    for m in _CREATE.finditer(text):
        table = _unquote(m.group("name").split(".")[-1])
        open_idx = m.end() - 1
        close_idx = _matching_paren(text, open_idx)
        body = text[open_idx + 1 : close_idx]
        for seg, off in _split_top_level(body):
            stripped = seg.lstrip()
            if not stripped:
                continue
            first = re.match(r"[\w\"`\[\]]+", stripped)
            if not first:
                continue
            ident = first.group(0)
            if _unquote(ident).lower() in _CONSTRAINT_WORDS:
                continue
            seg_offset = open_idx + 1 + off + (len(seg) - len(stripped))
            fields.append(Field(table, _unquote(ident), _line_of(text, seg_offset)))
    for m in _ALTER_ADD.finditer(text):
        table = _unquote(m.group("table").split(".")[-1])
        col = _unquote(m.group("col"))
        if col.lower() in _CONSTRAINT_WORDS:
            continue
        fields.append(Field(table, col, _line_of(text, m.start("col"))))
    return fields


# ---- Prisma -----------------------------------------------------------------

_PRISMA_BLOCK = re.compile(r"^\s*(?:model|type)\s+(?P<name>\w+)\s*\{", re.MULTILINE)
_PRISMA_FIELD = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)\s+(?P<type>[A-Za-z_]\w*)")


def parse_prisma(text: str) -> list[Field]:
    fields: list[Field] = []
    for m in _PRISMA_BLOCK.finditer(text):
        model = m.group("name")
        close = text.find("\n}", m.end())
        body_start = m.end()
        body = text[body_start : close if close != -1 else len(text)]
        line = _line_of(text, body_start)
        for raw in body.split("\n"):
            stripped = raw.strip()
            if stripped and not stripped.startswith(("@@", "//")):
                fm = _PRISMA_FIELD.match(raw)
                if fm:
                    fields.append(Field(model, fm.group("name"), line))
            line += 1
    return fields


# ---- OpenAPI / JSON Schema --------------------------------------------------

_OPENAPI_MARKERS = ("openapi", "swagger", "$schema", "components", "definitions", "properties")


def looks_like_schema_document(data: Any) -> bool:
    return isinstance(data, dict) and any(k in data for k in _OPENAPI_MARKERS)


def _walk(node: Any, crumb: list[str], out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            for key in props:
                out.append((".".join(crumb) or "schema", str(key)))
        params = node.get("parameters")
        if isinstance(params, list):
            for p in params:
                if isinstance(p, dict) and isinstance(p.get("name"), str):
                    out.append((".".join(crumb) or "parameters", p["name"]))
        for key, child in node.items():
            if key in (
                "example",
                "examples",
                "enum",
                "description",
                "x-amazon-apigateway-gateway-responses",
            ):
                continue
            _walk(child, [*crumb, str(key)], out)
    elif isinstance(node, list):
        for i, child in enumerate(node):
            _walk(child, [*crumb, str(i)], out)


def _key_line(text: str, key: str) -> int:
    pat = re.compile(rf'^\s*["\']?{re.escape(key)}["\']?\s*:', re.MULTILINE)
    m = pat.search(text)
    return _line_of(text, m.start()) if m else 0


def parse_schema_document(text: str) -> list[Field]:
    """OpenAPI 2/3 or JSON Schema, in JSON or YAML. Empty if it is neither."""
    data: Any
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return []
    if not looks_like_schema_document(data):
        return []
    pairs: list[tuple[str, str]] = []
    _walk(data, [], pairs)
    seen: set[tuple[str, str]] = set()
    fields: list[Field] = []
    for container, name in pairs:
        if (container, name) in seen:
            continue
        seen.add((container, name))
        # Trim the crumb to its last readable parts: components.schemas.User.properties
        short = ".".join(p for p in container.split(".") if p not in ("properties", "schema"))[-80:]
        fields.append(Field(short, name, _key_line(text, name)))
    return fields
