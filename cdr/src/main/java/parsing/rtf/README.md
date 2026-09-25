# Rich Text Format (RTF) Parser Subsystem (`parsing.rtf`)

The `parsing.rtf` package contains a custom lexical parser for Rich Text Format (`.rtf`) documents.

---

## 1. Current Release Status: RTF CDR Integrated

> [!WARNING]
> **RTF CDR is enabled in this integrated build.** The parser is used by the RTF threat analyzer and integrity validator. The release path now routes `.rtf` inputs through `RTFCDRProcessor`, which performs threat analysis, sanitization/reconstruction when required, and post-reconstruction validation.

| File | Responsibility |
|---|---|
| [`RTFParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFParser.java) | Main entry point coordinating group-aware lexing and extraction into `DocumentModel`. |
| [`RTFContentParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFContentParser.java) | Group-aware lexical scanner tracking brace depth (`{`, `}`), hex escapes (`\'hh`), and skipping non-content destination groups (`\fonttbl`, `\colortbl`, `\stylesheet`, `\info`). |
| [`RTFResourceParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFResourceParser.java) | Scans for embedded hex-encoded images (`\pict`) and embedded OLE objects (`\object`). |
| [`RTFHyperlinkExtractor.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFHyperlinkExtractor.java) | Extracts URLs from RTF field structures (`{\field{\*\fldinst HYPERLINK ...}}`). |
| [`RTFMetadataParser.java`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/parsing/rtf/RTFMetadataParser.java) | Extracts properties from the RTF `\info` group (title, author, creation date). |
