import hashlib
import json
from pathlib import Path


def calculate_sha256(file_path: str) -> str:
    """Calculate the SHA-256 hash of a file."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    sha256 = hashlib.sha256()

    with path.open("rb") as file:
        while chunk := file.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def create_baseline(directory: str, baseline_path: str) -> None:
    """Create a SHA-256 baseline for all files in a directory."""

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

    for file_path in sorted(directory_path.rglob("*")):
        if not file_path.is_file():
            continue

        try:
            file_hash = calculate_sha256(str(file_path))

            relative_path = file_path.relative_to(directory_path)

            baseline["files"][str(relative_path)] = {
                "sha256": file_hash,
                "size": file_path.stat().st_size
            }

        except (OSError, PermissionError) as error:
            print(
                f"Warning: Could not process "
                f"{file_path}: {error}"
            )

    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    with baseline_file.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4)

    print(f"Baseline created: {baseline_file}")
    print(f"Files recorded: {len(baseline['files'])}")


def load_baseline(baseline_path: str) -> dict:
    """Load a previously created baseline."""

    path = Path(baseline_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Baseline not found: {baseline_path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def check_integrity(directory: str, baseline_path: str) -> dict:
    """Compare current files against the trusted baseline."""

    directory_path = Path(directory)
    baseline = load_baseline(baseline_path)

    baseline_files = baseline.get("files", {})
    current_files = {}

    for file_path in sorted(directory_path.rglob("*")):
        if not file_path.is_file():
            continue

        try:
            relative_path = str(
                file_path.relative_to(directory_path)
            )

            current_files[relative_path] = {
                "sha256": calculate_sha256(str(file_path)),
                "size": file_path.stat().st_size
            }

        except (OSError, PermissionError) as error:
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

    return {
        "new": sorted(new_files),
        "modified": sorted(modified_files),
        "deleted": sorted(deleted_files)
    }


def print_report(results: dict) -> None:
    """Print an integrity verification report."""

    print("\nFILE INTEGRITY REPORT")
    print("=" * 24)

    print(f"\nNew files: {len(results['new'])}")
    for file_path in results["new"]:
        print(f"  [NEW]      {file_path}")

    print(f"\nModified files: {len(results['modified'])}")
    for file_path in results["modified"]:
        print(f"  [MODIFIED] {file_path}")

    print(f"\nDeleted files: {len(results['deleted'])}")
    for file_path in results["deleted"]:
        print(f"  [DELETED]  {file_path}")


if __name__ == "__main__":
    results = check_integrity(
        "monitored",
        "data/baseline.json"
    )

    print_report(results)
