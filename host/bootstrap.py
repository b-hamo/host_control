"""Bootstrap config: what the Runner needs to reach and trust the Host.

Written by the Host per session and mapped read-only into the Sandbox
(protocol doc §3, §4). The Runner reads it at start-up and must not need
anything else to connect.
"""

from __future__ import annotations

import json
from pathlib import Path

from host.session_registry import SessionRecord

BOOTSTRAP_VERSION = "1.0"
CONTROL_PATH = "/scrp/v1/control"
OBSERVATION_UPLOAD_PATH = "/scrp/v1/observations/"


def write_bootstrap(path: Path, rec: SessionRecord, cert_pem: str, port: int,
                    host: str | None = None, upload_port: int | None = None) -> None:
    data = {
        "bootstrap_version": BOOTSTRAP_VERSION,
        "session_id": rec.session_id,
        "runtime_id": rec.runtime_id,
        "generation": rec.generation,
        "host": host,                  # null: Runner uses its default gateway (Windows Sandbox)
        "port": port,
        "path": CONTROL_PATH,
        "token": rec.token,            # goes in the Authorization header, never in the URL or logs
        "token_expires_at": rec.expires_utc,
        "host_certificate_pem": cert_pem,
    }
    if upload_port is not None:
        # Screenshot uploads (protocol doc §8): PUT https://<host>:<upload_port><path><upload_id>,
        # same host rule and same pinned certificate as the control channel.
        data["observation_upload"] = {"port": upload_port, "path": OBSERVATION_UPLOAD_PATH}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
