# File Integrity Monitor

A Python-based file integrity monitoring tool that detects
unauthorized changes to monitored files using SHA-256 hashes.

## Project Status

🚧 Under Development

## Current Features

- SHA-256 file hashing
- Recursive file discovery
- JSON baseline generation
- File size tracking
- Basic filesystem error handling

## Current Status

Version 0.2 — Baseline generation implemented.

The project is currently under development. File modification,
deletion, and new-file detection will be implemented in upcoming
versions.

## Usage

### Create a baseline

bash
python3 -m src.fim baseline

## Planned Features

- File hashing
- Baseline creation
- File modification detection
- File deletion detection
- New file detection
- Security event logging
- Integrity reports

## Technology

- Python
- SHA-256
- JSON
- Git
- GitHub

## Author

Alwin Riyas
