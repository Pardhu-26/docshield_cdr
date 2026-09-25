# Security & Quarantine Subsystem (`security`)

## Overview

The `security` package provides core security controls and quarantine management for DocShield CDR. It ensures that untrusted input documents, damaged files, or files containing unremovable threats are safely isolated from users and host systems without executing active content.

## Key Classes & Architecture

### [`QuarantineManager`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/QuarantineManager.java)
- **Path**: `src/main/java/security/QuarantineManager.java`
- **Purpose**: Safely quarantines untrusted or malicious input files by copying them into an isolated repository directory with timestamped unique filenames, calculating their SHA-256 digests, and generating a forensic audit record note.
- **Workflow**:
  1. Validates that the input file exists and is a regular file.
  2. Creates the target directory `output/quarantine/` (resolved to absolute canonical path).
  3. Sanitizes the original filename (replaces all characters outside `[A-Za-z0-9._-]` with `_`).
  4. Generates a timestamped prefix in format `yyyyMMdd_HHmmss_SSS_<safeName>`.
  5. Creates an atomic temporary file in the quarantine directory, copies the source file with attributes preserved (`StandardCopyOption.COPY_ATTRIBUTES`), and performs an atomic move (`StandardCopyOption.ATOMIC_MOVE`) to `<prefix>.quarantined`.
  6. Computes the SHA-256 cryptographic digest of the quarantined file.
  7. Writes a companion diagnostic metadata file `<prefix>.quarantined.txt` recording the original absolute path, SHA-256 hash, and sanitized reason for quarantine.
- **Used by**: [`Main.java`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/Main.java) on format detection errors, extension spoofing, unremovable threats, integrity failures, empty input files, unsupported formats, or processing exceptions.

## Sub-Packages

- [`security.sandbox`](file:///D:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/security/sandbox/README.md): Host filesystem jail boundaries, hardened XML parser factory, and subprocess execution isolation.
