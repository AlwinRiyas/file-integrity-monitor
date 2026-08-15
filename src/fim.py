import argparse
import hashlib
import json
import logging
import os
import stat
from pathlib import Path


LOG_DIRECTORY = Path("logs")
LOG_FILE = LOG_DIRECTORY / "fim.log"

DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024


def setup_logging(
    log_file: Path = LOG_FILE
) -> logging.Logger:
    """Configure application security logging."""

    log_file = Path(log_file)

    log_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    try:
        log_file.touch(
            mode=0o600,
            exist_ok=True
        )
    except OSError:
        pass

    logger = logging.getLogger(
        f"fim.{log_file}"
    )

    logger.setLevel(logging.INFO)

    logger.handlers.clear()

    file_handler = logging.FileHandler(
        log_file,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(
        formatter
    )

    logger.addHandler(
        file_handler
    )

    logger.propagate = False

    return logger


def validate_file(
    file_path: Path,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
) -> None:
    """Validate a file before processing it."""

    if file_path.is_symlink():
        raise ValueError(
            f"Symbolic links are not allowed: {file_path}"
        )

    if not file_path.is_file():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    file_size = file_path.stat().st_size

    if file_size > max_file_size:
        raise ValueError(
            f"File exceeds maximum allowed size: "
            f"{file_path}"
        )


def calculate_sha256(
    file_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
) -> str:
    """Calculate the SHA-256 hash of a file."""

    path = Path(file_path)

    validate_file(
        path,
        max_file_size
    )

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(
    directory: str,
    baseline_path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
) -> None:
    """Create a SHA-256 baseline for all valid files."""

    directory_path = Path(directory)
    baseline_file = Path(baseline_path)

    if not directory_path.is_dir():
        raise NotADirectoryError(
            f"Directory not found: {directory}"
        )

    baseline = {
        "version": 1,
        "files": {}
    }

    for file_path in sorted(
        directory_path.rglob("*")
    ):
        if file_path.is_symlink():
            continue

        if not file_path.is_file():
            continue

        try:
            file_hash = calculate_sha256(
                str(file_path),
                max_file_size
            )

            relative_path = (
                file_path.relative_to(
                    directory_path
                )
            )

            baseline["files"][
                str(relative_path)
            ] = {
                "sha256": file_hash,
                "size": file_path.stat().st_size
            }

        except (
            OSError,
            PermissionError,
            ValueError
        ) as error:

            print(
                f"Warning: Could not process "
                f"{file_path}: {error}"
            )

    baseline_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with baseline_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            baseline,
            file,
            indent=4
        )

    try:
        baseline_file.chmod(0o600)
    except OSError:
        pass

    print(
        f"Baseline created: {baseline_file}"
    )

    print(
        f"Files recorded: "
        f"{len(baseline['files'])}"
    )


def validate_baseline(
    baseline: dict
) -> None:
    """Validate the structure of a baseline."""

    if not isinstance(
        baseline,
        dict
    ):
        raise ValueError(
            "Baseline must be a JSON object."
        )

    if baseline.get("version") != 1:
        raise ValueError(
            "Unsupported baseline version."
        )

    files = baseline.get("files")

    if not isinstance(
        files,
        dict
    ):
        raise ValueError(
            "Baseline 'files' must be an object."
        )

    for file_path, metadata in files.items():

        if not isinstance(
            file_path,
            str
        ):
            raise ValueError(
                "Baseline file paths must be strings."
            )

        if not isinstance(
            metadata,
            dict
        ):
            raise ValueError(
                f"Invalid metadata for: {file_path}"
            )

        sha256 = metadata.get(
            "sha256"
        )

        size = metadata.get(
            "size"
        )

        if (
            not isinstance(
                sha256,
                str
            )
            or len(sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in sha256
            )
        ):
            raise ValueError(
                f"Invalid SHA-256 hash for: "
                f"{file_path}"
            )

        if not isinstance(
            size,
            int
        ) or size < 0:
            raise ValueError(
                f"Invalid file size for: "
                f"{file_path}"
            )


def load_baseline(
    baseline_path: str
) -> dict:
    """Load and validate a baseline."""

    path = Path(baseline_path)

    if path.is_symlink():
        raise ValueError(
            "Baseline must not be a symbolic link."
        )

    if not path.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {baseline_path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8"
        ) as file:

            baseline = json.load(file)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid baseline JSON: {error}"
        ) from error

    validate_baseline(
        baseline
    )

    return baseline


def log_security_event(
    logger: logging.Logger,
    event_type: str,
    file_path: str,
    severity: str
) -> None:
    """Record a detected file integrity event."""

    logger.warning(
        "%s | %s | %s",
        severity,
        event_type,
        file_path
    )


def check_integrity(
    directory: str,
    baseline_path: str,
    logger: logging.Logger,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
) -> dict:
    """Compare current files against the baseline."""

    directory_path = Path(directory)

    if not directory_path.is_dir():
        raise NotADirectoryError(
            f"Directory not found: {directory}"
        )

    baseline = load_baseline(
        baseline_path
    )

    baseline_files = baseline.get(
        "files",
        {}
    )

    current_files = {}

    for file_path in sorted(
        directory_path.rglob("*")
    ):

        if file_path.is_symlink():
            logger.warning(
                "MEDIUM | SYMLINK_SKIPPED | %s",
                file_path
            )
            continue

        if not file_path.is_file():
            continue

        try:
            relative_path = str(
                file_path.relative_to(
                    directory_path
                )
            )

            current_files[
                relative_path
            ] = {
                "sha256": calculate_sha256(
                    str(file_path),
                    max_file_size
                ),
                "size": file_path.stat().st_size
            }

        except (
            OSError,
            PermissionError,
            ValueError
        ) as error:

            logger.warning(
                "MEDIUM | FILE_SKIPPED | %s | %s",
                file_path,
                error
            )

    new_files = []
    modified_files = []
    deleted_files = []

    for file_path in current_files:

        if file_path not in baseline_files:

            new_files.append(
                file_path
            )

        elif (
            current_files[file_path]["sha256"]
            != baseline_files[file_path]["sha256"]
        ):

            modified_files.append(
                file_path
            )

    for file_path in baseline_files:

        if file_path not in current_files:

            deleted_files.append(
                file_path
            )

    for file_path in new_files:

        log_security_event(
            logger,
            "NEW",
            file_path,
            "MEDIUM"
        )

    for file_path in modified_files:

        log_security_event(
            logger,
            "MODIFIED",
            file_path,
            "HIGH"
        )

    for file_path in deleted_files:

        log_security_event(
            logger,
            "DELETED",
            file_path,
            "HIGH"
        )

    return {
        "new": sorted(new_files),
        "modified": sorted(modified_files),
        "deleted": sorted(deleted_files)
    }


def print_report(
    results: dict
) -> None:
    """Print an integrity verification report."""

    print("\nFILE INTEGRITY REPORT")
    print("=" * 24)

    print(
        f"\nNew files: "
        f"{len(results['new'])}"
    )

    for file_path in results["new"]:

        print(
            f"  [NEW]      {file_path}"
        )

    print(
        f"\nModified files: "
        f"{len(results['modified'])}"
    )

    for file_path in results["modified"]:

        print(
            f"  [MODIFIED] {file_path}"
        )

    print(
        f"\nDeleted files: "
        f"{len(results['deleted'])}"
    )

    for file_path in results["deleted"]:

        print(
            f"  [DELETED]  {file_path}"
        )


def parse_arguments():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="File Integrity Monitor"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="Create a new integrity baseline"
    )

    baseline_parser.add_argument(
        "--directory",
        default="monitored",
        help="Directory to monitor"
    )

    baseline_parser.add_argument(
        "--output",
        default="data/baseline.json",
        help="Path to save the baseline"
    )

    baseline_parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help="Maximum file size in bytes"
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Check files against the integrity baseline"
    )

    check_parser.add_argument(
        "--directory",
        default="monitored",
        help="Directory to check"
    )

    check_parser.add_argument(
        "--baseline",
        default="data/baseline.json",
        help="Path to the baseline"
    )

    check_parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help="Maximum file size in bytes"
    )

    return parser.parse_args()


def main() -> None:
    """Application entry point."""

    args = parse_arguments()

    logger = setup_logging()

    try:

        if args.max_size <= 0:

            raise ValueError(
                "Maximum file size must be greater than zero."
            )

        if args.command == "baseline":

            create_baseline(
                args.directory,
                args.output,
                args.max_size
            )

        elif args.command == "check":

            results = check_integrity(
                args.directory,
                args.baseline,
                logger,
                args.max_size
            )

            print_report(
                results
            )

    except (
        FileNotFoundError,
        NotADirectoryError,
        PermissionError,
        ValueError,
        OSError
    ) as error:

        print(
            f"Error: {error}"
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
