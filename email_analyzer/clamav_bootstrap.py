"""Install the pinned official ClamAV portable runtime outside the repository."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

CLAMAV_VERSION = "1.5.4"
CLAMAV_ARCHIVE = f"clamav-{CLAMAV_VERSION}.win.x64.zip"
CLAMAV_URL = f"https://www.clamav.net/downloads/production/{CLAMAV_ARCHIVE}"
CLAMAV_SHA256 = "0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395"


def default_install_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    base = Path(local) if local else Path.home() / "AppData" / "Local"
    return base / "DISE" / "ClamAV" / f"clamav-{CLAMAV_VERSION}.win.x64"


def runtime_ready(root: Path) -> bool:
    return (root / "clamscan.exe").is_file() and (root / "freshclam.exe").is_file()


def database_ready(root: Path) -> bool:
    database = root / "database"
    # freshclam may install an incrementally updated database as ``.cld``
    # instead of ``.cvd``.  Both are valid ClamAV database formats.
    return all(
        any((database / f"{stem}.{suffix}").is_file() for suffix in ("cvd", "cld"))
        for stem in ("main", "daily", "bytecode")
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _wanted(relative: Path) -> bool:
    parts = relative.parts
    if len(parts) == 1:
        return relative.name in {"clamscan.exe", "freshclam.exe", "COPYING.txt"} or relative.suffix.lower() == ".dll"
    return parts[0] in {"certs", "COPYING"}


def extract_runtime(archive: Path, destination: Path) -> None:
    """Extract only runtime and licensing files from the verified official ZIP."""
    with zipfile.ZipFile(archive) as bundle:
        files = [entry for entry in bundle.infolist() if not entry.is_dir()]
        roots = {Path(entry.filename).parts[0] for entry in files if Path(entry.filename).parts}
        if len(roots) != 1:
            raise ValueError("unexpected_clamav_archive_layout")
        archive_root = next(iter(roots))
        for entry in files:
            path = Path(entry.filename)
            if not path.parts or path.parts[0] != archive_root:
                raise ValueError("unexpected_clamav_archive_path")
            relative = Path(*path.parts[1:])
            if not relative.parts or not _wanted(relative):
                continue
            target = destination / relative
            resolved = target.resolve()
            if destination.resolve() not in resolved.parents:
                raise ValueError("unsafe_clamav_archive_path")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _write_freshclam_config(root: Path) -> Path:
    database = root / "database"
    database.mkdir(parents=True, exist_ok=True)
    config = root / "freshclam.conf"
    config.write_text(
        f'DatabaseDirectory "{database}"\n'
        f'CVDCertsDirectory "{root / "certs"}"\n'
        'DatabaseMirror database.clamav.net\n'
        'ConnectTimeout 60\nReceiveTimeout 300\n',
        encoding="utf-8",
    )
    return config


def download_runtime(destination: Path, *, opener=urllib.request.urlopen, progress=None) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(CLAMAV_URL, headers={"User-Agent": "DISE-ClamAV-bootstrap/1"})
    with opener(request, timeout=120) as response, destination.open("wb") as output:
        total = int(response.headers.get("Content-Length", 0) or 0)
        received = 0
        next_report = 25 * 1024 * 1024
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
            received += len(chunk)
            if progress and (received >= next_report or (total and received == total)):
                progress(received, total)
                next_report += 25 * 1024 * 1024
    if _sha256(destination).casefold() != CLAMAV_SHA256:
        destination.unlink(missing_ok=True)
        raise ValueError("clamav_archive_hash_mismatch")
    return destination


def install_runtime(root: Path | None = None, *, progress=None) -> Path:
    root = (root or default_install_dir()).resolve()
    if runtime_ready(root):
        return root
    root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="dise-clamav-") as temporary:
        temporary_path = Path(temporary)
        archive = download_runtime(temporary_path / CLAMAV_ARCHIVE, progress=progress)
        staged = temporary_path / "runtime"
        staged.mkdir()
        extract_runtime(archive, staged)
        if not runtime_ready(staged):
            raise ValueError("clamav_runtime_incomplete")
        if root.exists():
            raise FileExistsError(f"incomplete ClamAV directory already exists: {root}")
        shutil.move(str(staged), str(root))
    _write_freshclam_config(root)
    return root


def update_signatures(root: Path, *, timeout: int = 900) -> None:
    config = _write_freshclam_config(root)
    completed = subprocess.run(
        [str(root / "freshclam.exe"), f"--config-file={config}"],
        capture_output=True, text=True, timeout=timeout, shell=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    # The usable database state is authoritative. freshclam can return a
    # non-zero status when one database is already current even though all
    # required databases are present and ready for clamscan.
    if not database_ready(root):
        message = (completed.stderr or completed.stdout or "freshclam_failed").strip().splitlines()[-1]
        raise RuntimeError(message)


def ensure_clamav(*, update: bool = True, progress=None) -> Path:
    root = install_runtime(progress=progress)
    ready_before_update = database_ready(root)
    if update or not ready_before_update:
        try:
            update_signatures(root)
        except (OSError, subprocess.SubprocessError):
            # A locked config/database or a temporary updater failure must not
            # disable scanning when a complete signed database is already on
            # disk. First-time preparation still fails until all DBs exist.
            if not ready_before_update or not database_ready(root):
                raise
    return root
