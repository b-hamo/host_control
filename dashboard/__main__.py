"""python -m dashboard: start the local read-only dashboard server (docs: dashboard/README.md)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dashboard.collect import KEEP_ENDED_S, VM_MAX, Collector, default_dashboard_dir, default_manager_root
from dashboard.server import DEFAULT_PORT, Dashboard, serve


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m dashboard", description=__doc__)
    ap.add_argument("--root", type=Path, action="append", default=[],
                    help="Sandbox Manager root to read (repeatable; the default root is always read, and "
                         "every --sandbox-root a running Host reports is added on its own)")
    ap.add_argument("--dashboard-dir", type=Path, default=default_dashboard_dir(),
                    help="where Hosts write their status (Host --dashboard-dir)")
    ap.add_argument("--static", type=Path, default=Path(__file__).resolve().parent / "static",
                    help="folder with the page (index.html)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--vm-max", type=int, default=VM_MAX, help="micro_VM concurrent limit shown as max")
    ap.add_argument("--keep-ended", type=float, default=KEEP_ENDED_S, help="seconds an ended session stays listed")
    ap.add_argument("--token", default=None, help="fixed token (default: a new random one each start)")
    ap.add_argument("--open", action="store_true", help="open the page in the default browser")
    a = ap.parse_args(argv)
    roots = [default_manager_root()] + [r for r in a.root if r != default_manager_root()]
    collector = Collector(roots, a.dashboard_dir, vm_max=a.vm_max, keep_ended_s=a.keep_ended)
    app = Dashboard(collector, a.token, a.static if a.static.is_dir() else None)
    server = serve(app, a.port)
    url = f"http://127.0.0.1:{server.server_address[1]}/?token={app.token}"
    print(f"SCRP dashboard: {url}", flush=True)
    if a.open:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
