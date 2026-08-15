import argparse
import hashlib
import json
import logging
from pathlib import Path


LOG_DIRECTORY = Path("logs")
LOG_FILE = LOG_DIRECTORY / "fim.log"


def setup_logging(
    log_file: Path = LOG_FILE
) -> logging.Logger:
    """Configure application security logging."""

    log_file = Path(log_file)

    log_file.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    logger = logging.getLogger(
        f"fim.{log_file}"
    )

    logger.setLevel(
        logging.INFO
    )

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


def calculate_sha256(
    file_path: str
) -> str:
    """Calculate the SHA-256 hash of a file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(
    directory: str,
    baseline_path: str
) -> None:
    """Create a SHA-256 baseline for all files."""

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
        if not file_path.is_file():
            continue

        try:
            file_hash = calculate_sha256(
                str(file_path)
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
            PermissionError
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

    print(
        f"Baseline created: {baseline_file}"
    )

    print(
        f"Files recorded: "
        f"{len(baseline['files'])}"
    )


def load_baseline(
    baseline_path: str
) -> dict:
    """Load a previously created baseline."""

    path = Path(baseline_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {baseline_path}"
        )

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


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
    logger: logging.Logger
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
        if not file_path.is_file():
            continue

        try:
            relative_path = str(
                file_path.relative_to(
                    directory_path
                )
            )

            current_files[relative_path] = {
                "sha256": calculate_sha256(
                    str(file_path)
                ),
                "size": file_path.stat().st_size
            }

        except (
            OSError,
            PermissionError
        ) as error:
            print(
                f"Warning: Could not process "
                f"{file_path}: {error}"
            )

    new_files = []
    modified_files = []
    deleted_files = []

    for file_path in current_files:

        if file_path not in baseline_files:
            new_files.append(file_path)

        elif (
            current_files[file_path]["sha256"]
            != baseline_files[file_path]["sha256"]
        ):
            modified_files.append(file_path)

    for file_path in baseline_files:

        if file_path not in current_files:
            deleted_files.append(file_path)

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

    return parser.parse_args()


def main() -> None:
    """Application entry point."""

    args = parse_arguments()

    logger = setup_logging()

    try:

        if args.command == "baseline":

            create_baseline(
                args.directory,
                args.output
            )

        elif args.command == "check":

            results = check_integrity(
                args.directory,
                args.baseline,
                logger
            )

            print_report(results)

    except (
        FileNotFoundError,
        NotADirectoryError,
        PermissionError,
        json.JSONDecodeError
    ) as error:

        print(
            f"Error: {error}"
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
