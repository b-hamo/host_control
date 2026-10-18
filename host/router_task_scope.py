"""Load user task scope from a Host-owned file, never from page text/tool claims."""
import json
from pathlib import Path
from host.router_web_policy import WebPolicy


def load_task(path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or path.is_junction():
        raise ValueError('Task file must be a regular absolute Host path')
    raw = path.read_bytes()
    if len(raw) > 65536:
        raise ValueError('Task file too large')
    doc = json.loads(raw)
    if (set(doc) != {'goal', 'urls'} or not isinstance(doc['goal'], str)
            or not doc['goal'].strip() or len(doc['goal']) > 8192
            or not isinstance(doc['urls'], list) or not 1 <= len(doc['urls']) <= 64):
        raise ValueError('Task file requires a goal and 1-64 explicit user URLs')
    origins = sorted({WebPolicy.origin(url) for url in doc['urls']})
    if any('*' in origin for origin in origins):
        raise ValueError('Task URLs cannot contain wildcards')
    return {'goal': doc['goal'], 'origins': origins}
