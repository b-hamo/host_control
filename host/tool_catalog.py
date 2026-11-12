"""The MCP tools the Agent may call, loaded from schema/mcp-tools/ (WBS 2.4).

Spec B-2: every tool input is validated against its declared schema (type,
required fields, enums, lengths, ranges, no unknown fields) before anything
reaches the next layer. Spec B-11: the Agent only sees tools this session can
actually use; the rest are hidden and, if called anyway, refused here.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path

from jsonschema import Draft202012Validator

from host.tool_availability import unavailable_reason
from scrp.validate import SCHEMA_DIR

TOOLS_DIR = SCHEMA_DIR / "mcp-tools"


class ToolError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    input_schema: dict
    annotations: dict

    def as_mcp(self) -> dict:
        return {"name": self.name, "description": self.description,
                "inputSchema": self.input_schema, "annotations": self.annotations}


class ToolCatalog:
    def __init__(self, tools_dir: Path = TOOLS_DIR):
        self._tools: dict[str, ToolDef] = {}
        self._validators: dict[str, Draft202012Validator] = {}
        for path in sorted(tools_dir.glob("*.json")):
            d = json.loads(path.read_text(encoding="utf-8"))
            self._tools[d["name"]] = ToolDef(d["name"], d["description"], d["inputSchema"], d["annotations"])
            self._validators[d["name"]] = Draft202012Validator(d["inputSchema"])

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def get(self, name: str) -> ToolDef:
        if name not in self._tools:
            raise ToolError("INVALID_ARGUMENT", f"unknown tool {name!r}")
        return self._tools[name]

    def unavailable_reason(self, name: str, granted: set[str]) -> str | None:
        return unavailable_reason(name, granted)

    def available(self, granted: set[str]) -> list[ToolDef]:
        return [t for n, t in self._tools.items() if self.unavailable_reason(n, granted) is None]

    def validate(self, name: str, arguments: dict | None) -> dict:
        """Schema check, then fill declared defaults (models often omit them)."""
        tool = self.get(name)
        args = {} if arguments is None else arguments
        if not isinstance(args, dict):
            raise ToolError("INVALID_ARGUMENT", "arguments must be an object")
        errors = sorted(self._validators[name].iter_errors(args), key=lambda e: list(e.path))
        if errors:
            e = errors[0]
            where = ".".join(str(p) for p in e.path) or "arguments"
            raise ToolError("INVALID_ARGUMENT", f"{where}: {e.message[:200]}")
        filled = copy.deepcopy(args)
        for key, prop in tool.input_schema.get("properties", {}).items():
            if key not in filled and "default" in prop:
                filled[key] = copy.deepcopy(prop["default"])
        return filled
