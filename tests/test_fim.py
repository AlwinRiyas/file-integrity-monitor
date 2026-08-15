import json
import tempfile
import unittest
from pathlib import Path

from src.fim import (
    calculate_sha256,
    check_integrity,
    create_baseline,
    setup_logging,
)


class TestFileIntegrityMonitor(unittest.TestCase):
    """Test the File Integrity Monitor."""

    def setUp(self):
        """Create an isolated temporary test environment."""

        self.temp_dir = tempfile.TemporaryDirectory()

        self.test_root = Path(
            self.temp_dir.name
        )

        self.monitored_dir = (
            self.test_root / "monitored"
        )

        self.baseline_file = (
            self.test_root / "baseline.json"
        )

        self.log_file = (
            self.test_root / "test.log"
        )

        self.monitored_dir.mkdir()

        self.test_file = (
            self.monitored_dir / "test.txt"
        )

        self.test_file.write_text(
            "original content",
            encoding="utf-8"
        )

        self.logger = setup_logging(
            self.log_file
        )

    def tearDown(self):
        """Remove the temporary test environment."""

        self.temp_dir.cleanup()

    def test_sha256_hash(self):
        """Verify SHA-256 hashing."""

        file_hash = calculate_sha256(
            str(self.test_file)
        )

        self.assertEqual(
            len(file_hash),
            64
        )

        self.assertRegex(
            file_hash,
            r"^[a-f0-9]{64}$"
        )

    def test_create_baseline(self):
        """Verify baseline creation."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        self.assertTrue(
            self.baseline_file.exists()
        )

        with self.baseline_file.open(
            "r",
            encoding="utf-8"
        ) as file:
            baseline = json.load(file)

        self.assertIn(
            "files",
            baseline
        )

        self.assertIn(
            "test.txt",
            baseline["files"]
        )

    def test_no_changes(self):
        """Verify unchanged files."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        results = check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertEqual(
            results["new"],
            []
        )

        self.assertEqual(
            results["modified"],
            []
        )

        self.assertEqual(
            results["deleted"],
            []
        )

    def test_modified_file(self):
        """Verify modified file detection."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        self.test_file.write_text(
            "modified content",
            encoding="utf-8"
        )

        results = check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertIn(
            "test.txt",
            results["modified"]
        )

    def test_new_file(self):
        """Verify new file detection."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        new_file = (
            self.monitored_dir / "new.txt"
        )

        new_file.write_text(
            "new file",
            encoding="utf-8"
        )

        results = check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertIn(
            "new.txt",
            results["new"]
        )

    def test_deleted_file(self):
        """Verify deleted file detection."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        self.test_file.unlink()

        results = check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertIn(
            "test.txt",
            results["deleted"]
        )

    def test_multiple_changes(self):
        """Verify multiple changes."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        self.test_file.write_text(
            "changed",
            encoding="utf-8"
        )

        new_file = (
            self.monitored_dir / "new.txt"
        )

        new_file.write_text(
            "new",
            encoding="utf-8"
        )

        results = check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertIn(
            "test.txt",
            results["modified"]
        )

        self.assertIn(
            "new.txt",
            results["new"]
        )

    def test_invalid_directory(self):
        """Verify invalid directory handling."""

        with self.assertRaises(
            NotADirectoryError
        ):
            check_integrity(
                str(
                    self.test_root
                    / "does-not-exist"
                ),
                str(self.baseline_file),
                self.logger
            )

    def test_logging(self):
        """Verify security events are logged."""

        create_baseline(
            str(self.monitored_dir),
            str(self.baseline_file)
        )

        self.test_file.write_text(
            "malicious-looking change",
            encoding="utf-8"
        )

        check_integrity(
            str(self.monitored_dir),
            str(self.baseline_file),
            self.logger
        )

        self.assertTrue(
            self.log_file.exists()
        )

        log_content = (
            self.log_file.read_text(
                encoding="utf-8"
            )
        )

        self.assertIn(
            "MODIFIED",
            log_content
        )

        self.assertIn(
            "test.txt",
            log_content
        )


if __name__ == "__main__":
    unittest.main()
