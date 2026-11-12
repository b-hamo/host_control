"""SecureArtifactScanner: a separate Windows service that receives, scans and disposes artifacts.

Runs as the virtual service account NT SERVICE\\SecureArtifactScanner (no administrator,
no LocalSystem), scans with Microsoft Defender's MpCmdRun.exe and talks to the Host only
over an ACL-restricted Named Pipe. It never shares memory or globals with host/.
See scanner_service/README.md.
"""

__version__ = "0.1.0"
