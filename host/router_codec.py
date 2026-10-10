"""Strict JSON boundary shared by Router MCP and trusted Host provisioning."""

from dataclasses import fields

from router.models import Action, Command, Location, Operation, Scope, Source, Task


def exact(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or not set(required) <= value.keys():
        raise ValueError("invalid object fields")
    return value


def strings(value):
    if not isinstance(value, list) or len(value) > 128 or any(not isinstance(v, str) for v in value):
        raise ValueError("string array required")
    return tuple(value)


def source(value):
    data = dict(exact(value, {f.name for f in fields(Source)}, ("source_id", "reference", "sha256", "origin")))
    data["parents"] = strings(data.get("parents", []))
    return Source(**data)


def scope(value):
    exact(value, {f.name for f in fields(Scope)})
    return Scope(**{k: strings(v) for k, v in value.items()})


def action(value):
    data = dict(exact(value, {f.name for f in fields(Action)},
                      ("action_id", "task_id", "operation", "scope", "delegation_ref")))
    data["operation"] = Operation(data["operation"])
    data["scope"] = scope(data["scope"])
    values = data.get("sources", [])
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError("source array required")
    data["sources"] = tuple(source(s) for s in values)
    if data.get("command") is not None:
        cmd = dict(exact(data["command"], {f.name for f in fields(Command)},
                         ("executable", "argv", "cwd", "target_source")))
        cmd["argv"] = strings(cmd["argv"])
        data["command"] = Command(**cmd)
    for key in ("inputs", "outputs", "depends_on"):
        data[key] = strings(data.get(key, []))
    return Action(**data)


def task(value):
    data = dict(exact(value, {f.name for f in fields(Task)}, ("task_id", "location")))
    data["location"] = Location(data["location"])
    data["depends_on"] = strings(data.get("depends_on", []))
    return Task(**data)
