import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import zipfile

from email_analyzer.clamav_bootstrap import database_ready, ensure_clamav, extract_runtime, runtime_ready


class ClamAVBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_extracts_runtime_and_omits_development_files(self):
        archive = self.root / "clamav.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("clamav-1.5.4.win.x64/clamscan.exe", b"scan")
            bundle.writestr("clamav-1.5.4.win.x64/freshclam.exe", b"update")
            bundle.writestr("clamav-1.5.4.win.x64/libclamav.dll", b"dll")
            bundle.writestr("clamav-1.5.4.win.x64/certs/clamav.crt", b"cert")
            bundle.writestr("clamav-1.5.4.win.x64/COPYING.txt", b"license")
            bundle.writestr("clamav-1.5.4.win.x64/libclamav.pdb", b"debug")
            bundle.writestr("clamav-1.5.4.win.x64/clamav_rust.lib", b"development")
        destination = self.root / "runtime"
        destination.mkdir()
        extract_runtime(archive, destination)
        self.assertTrue(runtime_ready(destination))
        self.assertTrue((destination / "libclamav.dll").is_file())
        self.assertTrue((destination / "certs" / "clamav.crt").is_file())
        self.assertFalse((destination / "libclamav.pdb").exists())
        self.assertFalse((destination / "clamav_rust.lib").exists())

    def test_rejects_archive_with_multiple_roots(self):
        archive = self.root / "bad.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr("one/clamscan.exe", b"scan")
            bundle.writestr("two/freshclam.exe", b"update")
        destination = self.root / "runtime"
        destination.mkdir()
        with self.assertRaises(ValueError):
            extract_runtime(archive, destination)

    def make_ready_install(self, *, database=True):
        (self.root / "clamscan.exe").write_bytes(b"scan")
        (self.root / "freshclam.exe").write_bytes(b"update")
        if database:
            folder = self.root / "database"
            folder.mkdir()
            for name in ("main.cvd", "daily.cld", "bytecode.cvd"):
                (folder / name).write_bytes(b"database")

    def test_existing_database_survives_locked_update_files(self):
        self.make_ready_install()
        self.assertTrue(database_ready(self.root))
        with patch("email_analyzer.clamav_bootstrap.default_install_dir", return_value=self.root), \
             patch("email_analyzer.clamav_bootstrap.update_signatures", side_effect=PermissionError("locked")):
            self.assertEqual(ensure_clamav(), self.root.resolve())

    def test_first_install_still_fails_when_database_update_fails(self):
        self.make_ready_install(database=False)
        with patch("email_analyzer.clamav_bootstrap.default_install_dir", return_value=self.root), \
             patch("email_analyzer.clamav_bootstrap.update_signatures", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                ensure_clamav()


if __name__ == "__main__":
    unittest.main()
