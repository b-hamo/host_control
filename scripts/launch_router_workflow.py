"""Start the presentation Router with an explicit Host configuration file."""
from pathlib import Path
import os
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

if __name__ == '__main__':
    # The optional sibling checkout is used by the original integration layout.
    manager = ROOT.parent / 'sandbox_manager'
    if manager.is_dir():
        sys.path.insert(0, str(manager))
    if os.name == 'nt':
        os.environ['PSModulePath'] = os.pathsep.join([
            str(Path(os.environ['WINDIR']) / 'System32/WindowsPowerShell/v1.0/Modules'),
            str(Path(os.environ['ProgramFiles']) / 'WindowsPowerShell/Modules')])
    from host.router_workflow_server import main
    main()
