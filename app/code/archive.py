"""Reads uploaded archives (.zip source, .apk, .ipa) in memory, with limits.

Nothing is extracted to disk, so hostile paths like ../../etc/passwd are harmless, and
decompressed size is capped so a zip bomb can't exhaust memory.
"""

import io
import posixpath
import zipfile
from dataclasses import dataclass

MAX_ENTRIES = 50_000
MAX_TEXT_FILE_BYTES = 1_000_000
MAX_TEXT_TOTAL_BYTES = 60_000_000
MAX_BINARY_FILE_BYTES = 80_000_000
MAX_RATIO = 200  # compressed -> uncompressed; real code rarely exceeds ~20

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "bower_components", "dist", "build", ".next", "out", "target",
    "Pods", ".venv", "venv", "env", "__pycache__", ".gradle", ".idea", "coverage", ".dart_tool",
    "DerivedData", "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "__MACOSX", ".expo",
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".svelte", ".php", ".java", ".kt", ".kts",
    ".go", ".rb", ".cs", ".swift", ".m", ".dart", ".rs", ".scala", ".html", ".htm", ".xml", ".plist",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".gradle", ".env", ".txt",
    ".lock", ".rules", ".sh", ".sql", ".tf", ".erb", ".ejs", ".hbs", ".twig", ".jinja", ".j2", ".resolved",
}
TEXT_NAMES = {"Dockerfile", "Gemfile", "Podfile", "Procfile", "go.mod", "go.sum", ".npmrc", ".pypirc", "Makefile"}


class ArchiveError(ValueError):
    pass


@dataclass
class SourceFile:
    path: str
    text: str

    @property
    def name(self) -> str:
        return posixpath.basename(self.path)

    @property
    def ext(self) -> str:
        return posixpath.splitext(self.path)[1].lower()


def detect_kind(filename: str) -> str:
    lower = filename.lower()
    if lower.endswith(".apk"):
        return "apk"
    if lower.endswith(".ipa"):
        return "ipa"
    if lower.endswith(".zip"):
        return "source"
    if lower.endswith(".aab"):
        raise ArchiveError("App bundles (.aab) aren't supported yet. Build an APK and upload that instead.")
    raise ArchiveError("Upload a .zip of your project, an Android .apk, or an iOS .ipa.")


def is_text_candidate(path: str) -> bool:
    base = posixpath.basename(path)
    ext = posixpath.splitext(base)[1].lower()
    return ext in TEXT_EXTENSIONS or base in TEXT_NAMES or base.startswith(".env")


class Archive:
    def __init__(self, data: bytes):
        try:
            self.zip = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            raise ArchiveError("That file isn't a valid zip archive.")
        infos = [i for i in self.zip.infolist() if not i.is_dir()]
        if len(infos) > MAX_ENTRIES:
            raise ArchiveError(f"The archive has more than {MAX_ENTRIES:,} files.")
        for info in infos:
            if info.file_size > 1_000_000 and info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise ArchiveError("The archive looks like a zip bomb (suspicious compression ratio).")
        self.infos = infos
        self.root = self._common_root()

    def _common_root(self) -> str:
        """GitHub-style zips wrap everything in one folder; strip it from displayed paths."""
        tops = {i.filename.split("/", 1)[0] for i in self.infos if "/" in i.filename}
        if len(tops) == 1 and all("/" in i.filename for i in self.infos):
            return tops.pop() + "/"
        return ""

    def display_path(self, info: zipfile.ZipInfo) -> str:
        path = info.filename[len(self.root):] if self.root else info.filename
        return posixpath.normpath("/" + path).lstrip("/")

    def names(self) -> list[str]:
        return [i.filename for i in self.infos]

    def read(self, name: str, limit: int = MAX_BINARY_FILE_BYTES) -> bytes:
        info = self.zip.getinfo(name)
        if info.file_size > limit:
            raise ArchiveError(f"{name} is too large to analyze.")
        with self.zip.open(info) as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ArchiveError(f"{name} is too large to analyze.")
        return data

    def text_files(self) -> tuple[list[SourceFile], int]:
        """Returns (readable text files, number of files skipped for size/limits)."""
        files, total, skipped = [], 0, 0
        for info in self.infos:
            path = self.display_path(info)
            if set(path.split("/")[:-1]) & SKIP_DIRS or not is_text_candidate(path):
                continue
            if info.file_size > MAX_TEXT_FILE_BYTES or total + info.file_size > MAX_TEXT_TOTAL_BYTES:
                skipped += 1
                continue
            with self.zip.open(info) as handle:
                raw = handle.read(MAX_TEXT_FILE_BYTES + 1)
            if b"\x00" in raw[:8192]:
                continue  # binary file with a text-like name
            total += len(raw)
            files.append(SourceFile(path, raw.decode("utf-8", errors="replace")))
        return files, skipped
