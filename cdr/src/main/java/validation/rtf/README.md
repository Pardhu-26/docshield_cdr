# RTF Integrity Validator Subsystem (`validation.rtf`)

The `validation.rtf` package provides structural and syntactic validation for reconstructed Rich Text Format (`.rtf`) files before release.

---

## 1. Validation Criteria

1. **Existence and Non-Emptiness**: Output file exists, is a regular file, and size > 0.
2. **Magic Signature**: Validates standard RTF signature (`{\rtf`) allowing optional UTF-8 BOM and leading whitespace.
3. **Strict Group Balancing**: Tracks brace depth (`{`, `}`) across the stream. Rejects underflows (`depth < 0`) and unclosed groups (`final depth != 0`).
4. **Semantic Parser Ingest**: Confirms that `RTFParser` successfully loads the document into a `DocumentModel` without throwing exceptions.
