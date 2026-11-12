"""Retired cross-conversation takeover API.

A new Host never owns another Host's process or VM. Keep these entry points
inert for older integrations importing them; binding an occupied port must
fail normally. VM recovery belongs to the session's lifecycle owner.
"""
from __future__ import annotations


def take_over(ports: tuple[int, ...], **legacy_options) -> list[int]:
    """Compatibility no-op: never inspect, terminate, or wait for another Host."""
    return []


def reclaim_sandboxes(root=None) -> list[str]:
    """Compatibility no-op: starting a chat does not authorize VM reclamation."""
    return []
