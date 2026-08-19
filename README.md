# VERITAS

### Cryptographic File Integrity Monitoring System

> **Veritas** — Latin for *truth* — is a lightweight, security-focused File Integrity Monitoring (FIM) system that uses SHA-256 cryptographic hashing to establish a trusted filesystem baseline and detect unauthorized file changes.

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Hashing](https://img.shields.io/badge/Hash-SHA--256-green)
![Testing](https://img.shields.io/badge/Testing-Unittest-orange)
![Status](https://img.shields.io/badge/Status-Stable-success)

---

## 📌 Overview

File integrity is a fundamental security control used to detect unauthorized changes to important files.

Attackers may modify configuration files, application files, scripts, security policies, or other sensitive resources after gaining access to a system.

**Veritas** addresses this problem by creating a trusted cryptographic baseline of a monitored directory and comparing future filesystem states against that baseline.

It detects:

- 🔴 Modified files
- 🟡 Newly created files
- ⚫ Deleted files

Instead of relying only on timestamps or filenames, Veritas uses **SHA-256 cryptographic hashes** to represent file contents.

---

## 🎯 Objectives

The primary objectives of Veritas are to:

- Establish a trusted filesystem baseline
- Detect unauthorized file modifications
- Detect newly created files
- Detect deleted files
- Provide security-focused logging
- Validate filesystem inputs
- Protect against unsafe symbolic-link traversal
- Control resource consumption during hashing
- Provide automated tests for core security functionality
- Demonstrate practical File Integrity Monitoring concepts

---

# ⚙️ How Veritas Works

Veritas follows a simple but security-focused workflow:

```text
                    ┌─────────────────────┐
                    │  Monitored Folder   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  File Discovery     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Input Validation   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │    SHA-256 Hash     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Trusted Baseline   │
                    │       JSON          │
                    └──────────┬──────────┘
                               │
                         Later Scan
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Current State     │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Baseline Comparison │
                    └──────────┬──────────┘
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
          ┌──────────┐    ┌──────────┐    ┌──────────┐
          │ MODIFIED │    │   NEW    │    │ DELETED  │
          └──────────┘    └──────────┘    └──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Security Logging   │
                    └─────────────────────┘