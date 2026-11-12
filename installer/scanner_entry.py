"""PyInstaller entry point of SecureArtifactScanner.exe (see installer/build.ps1)."""

import sys

from scanner_service.service import main

if __name__ == "__main__":
    sys.exit(main())
