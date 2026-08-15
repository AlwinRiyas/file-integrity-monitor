# Threat Model

## Purpose

This document describes the security threats considered by the File
Integrity Monitor.

The goal is to understand what the FIM protects against and where its
current limitations exist.

## Assets

The primary assets are:

1. Monitored files
2. Integrity baseline
3. Security logs
4. FIM source code
5. Integrity reports

## Threat Actors

Potential threat actors include:

### Local Attacker

An attacker who has obtained some level of access to the monitored
system.

### Malware

Malicious software attempting to modify files without authorization.

### Compromised User Account

A user account that has been compromised by an attacker.

## Threats

### T1 — Unauthorized File Modification

An attacker modifies a monitored file.

Example:

```text
config.txt
    |
    v
Attacker changes content
    |
    v
SHA-256 changes
    |
    v
FIM detects MODIFIED
