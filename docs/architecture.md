# Architecture

## Overview

The File Integrity Monitor (FIM) is a Python-based security utility
that detects unauthorized or unexpected filesystem changes.

The application compares the current state of monitored files against
a previously generated trusted baseline.

## High-Level Architecture

```text
User
 |
 v
Command Line Interface
 |
 +----------------------+
 |                      |
 v                      v
Baseline Command       Check Command
 |                      |
 v                      v
File Discovery        Load Baseline
 |                      |
 v                      v
SHA-256 Hashing       File Discovery
 |                      |
 v                      v
JSON Baseline          SHA-256 Hashing
                        |
                        v
                    Comparison
                        |
              +---------+---------+
              |         |         |
              v         v         v
             NEW    MODIFIED   DELETED
              |         |         |
              +---------+---------+
                        |
                        v
                 Security Logging
