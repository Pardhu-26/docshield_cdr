# RTF CDR Processor Subsystem (`processing.rtf`)

The `processing.rtf` package contains the high-assurance Content Disarm and Reconstruction pipeline for Rich Text Format documents (`.rtf`).

---

## 1. Pipeline Stages

1. **Anti-Spoofing & Ingestion**: Verifies that the input is a valid RTF file matching its extension.
2. **Capability-Based Inspection**: `RTFThreatAnalyzer` inspects the document structure for embedded objects, Equation Editor exploits, DDE fields, external templates, and dangerous URI targets.
3. **Zero-Trust Clean Fast-Path**: If no blocking findings exist, copies the original file with byte-for-byte SHA-256 verification.
4. **Disarm & Reconstruction**: `RTFThreatSanitizer` excises active constructs, replaces DDE with static cached text, neutralizes dangerous URIs, and serializes the clean document.
5. **Multi-Pass Integrity Gate**: Re-reads the reconstructed document from disk. Verifies structure with `RTFIntegrityValidator` and re-analyzes for residual threats with `RTFThreatAnalyzer`.
6. **Audit & Reporting**: Produces universal CDR summary and audit log.
