"""Where keyleak remembers the last run, so `report` can build an HTML file later.

Everything lives under ~/.keyleak (override with KEYLEAK_HOME). Files are plain JSON
with datetimes as ISO-8601 strings. Nothing secret is stored: key IDs are not secrets.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INVESTIGATE_FILE = "last_investigate.json"
SWEEP_FILE = "last_sweep.json"
ACTIONS_FILE = "actions.json"


def state_dir() -> Path:
    override = os.environ.get("KEYLEAK_HOME")
    base = Path(override) if override else Path.home() / ".keyleak"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Cannot serialise {type(obj).__name__}")


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False, default=_default)


def save(name: str, data: Any) -> Path:
    path = state_dir() / name
    path.write_text(dumps(data), encoding="utf-8")
    return path


def load(name: str) -> Any | None:
    path = state_dir() / name
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def append_action(action: dict[str, Any]) -> Path:
    existing = load(ACTIONS_FILE) or []
    if not isinstance(existing, list):
        existing = []
    action = dict(action)
    action.setdefault("at", datetime.now(timezone.utc).isoformat())
    existing.append(action)
    return save(ACTIONS_FILE, existing)


def load_actions() -> list[dict[str, Any]]:
    data = load(ACTIONS_FILE)
    return data if isinstance(data, list) else []
