# File Integrity Monitor

A Python-based cybersecurity tool that detects filesystem changes
using SHA-256 cryptographic hashes.

The project is designed as a practical security engineering project
covering file integrity monitoring, security logging, automated
testing, input validation, and secure development practices.

## Project Status

**Version:** 0.9  
**Status:** Portfolio development

## Why This Project?

File Integrity Monitoring (FIM) is a security technique used to detect
unexpected changes to important files.

A typical workflow is:

```text
Trusted State
     |
     v
SHA-256 Baseline
     |
     v
Filesystem Scan
     |
     v
Hash Comparison
     |
     v
Change Detection
     |
     v
Security Event
