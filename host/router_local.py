"""Fixed Local data tools. The root must be a Host-owned data-only directory.

No process API. Not an OS boundary against concurrent filesystem attackers.
Browser providers must independently enforce redirects and network scope.
"""

from pathlib import Path
import hashlib
import os

from router.models import Action, Operation


class LocalTools:
    def __init__(self, root: Path, *, browse=None, search=None, max_bytes: int = 1024 * 1024):
        self.root = root.resolve(strict=True)
        self.browse, self.search, self.max_bytes = browse, search, max_bytes
        self.results: dict[str, bytes] = {}

    def _path(self, value: str) -> Path:
        raw = Path(value)
        if not raw.is_absolute() or ".." in raw.parts:
            raise ValueError("absolute data path required")
        for part in (raw, *raw.parents):
            if part.is_symlink() or part.is_junction():
                raise ValueError("indirect data path refused")
        path = raw.resolve()
        if not path.is_relative_to(self.root) or path == self.root:
            raise ValueError("outside data root")
        if ":" in path.name or path.name.rstrip(". ") != path.name or \
                getattr(os.path, "isreserved", lambda p: False)(path):
            raise ValueError("special path refused")
        return path

    def validate(self, action: Action, final_ref: str = "") -> None:
        if action.operation == Operation.READ_TEXT:
            value = final_ref or action.locator
            if value not in action.scope.reads or action.scope.writes or action.outputs:
                raise ValueError("read scope mismatch")
            self._path(value)
        elif action.operation == Operation.WRITE_TEXT:
            if action.locator not in action.scope.writes or action.scope.reads or action.inputs or action.outputs:
                raise ValueError("write scope mismatch")
            if self._path(action.locator).suffix.lower() != ".txt":
                raise ValueError("only TXT data writes")
            if len(action.text.encode()) > self.max_bytes:
                raise ValueError("text too large")
        elif action.operation in {Operation.SEARCH, Operation.BROWSE}:
            if action.scope.reads or action.scope.writes or not action.scope.network or action.inputs or action.outputs:
                raise ValueError("browser scope mismatch")
            if (self.browse if action.operation == Operation.BROWSE else self.search) is None:
                raise ValueError("read-only browser provider unavailable")
        else:
            raise ValueError("no Local execution tool")
        if action.scope.capabilities:
            raise ValueError("Local tool does not grant additional capabilities")
        if action.operation in {Operation.READ_TEXT, Operation.WRITE_TEXT} and action.scope.network:
            raise ValueError("file tools do not use network")

    async def run(self, action: Action, final_ref: str = "") -> tuple[str, str]:
        self.validate(action, final_ref)
        if action.operation == Operation.READ_TEXT:
            with self._path(final_ref or action.locator).open("rb") as stream:
                data = stream.read(self.max_bytes + 1)
            data.decode("utf-8")
        elif action.operation == Operation.WRITE_TEXT:
            path = self._path(action.locator)
            path.write_text(action.text, encoding="utf-8", newline="")
            data = path.read_bytes()
            if data != action.text.encode():
                raise ValueError("write verification failed")
        else:
            provider = self.browse if action.operation == Operation.BROWSE else self.search
            data = await provider(action)
        if not isinstance(data, bytes) or len(data) > self.max_bytes:
            raise ValueError("invalid or oversized result")
        checksum = hashlib.sha256(data).hexdigest()
        result_id = "DATA-" + checksum
        self.results[result_id] = data
        return result_id, checksum
