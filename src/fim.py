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
            print(f"Warning: Could not process {file_path}: {error}")

    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    with baseline_file.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=4)

    print(f"Baseline created: {baseline_file}")
    print(f"Files recorded: {len(baseline['files'])}")


if __name__ == "__main__":
    create_baseline("monitored", "data/baseline.json")
