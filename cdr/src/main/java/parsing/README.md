# Parsing Subsystem (`parsing`)

The `parsing` package contains the document ingest engines, physical OPC package readers, semantic metadata extractors, and legacy format conversion bridges.

---

## 1. Architectural Organization

DocShield separates **Physical Package Reading** from **Semantic Metadata Extraction**:

1. **Physical Package Reading (`parsing.ooxml.OOXMLPackageReader`)**: Ingests raw ZIP archives into memory representations ([`OOXMLPackage`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPackage.java), [`OOXMLPart`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLPart.java), [`OOXMLRelationship`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/ooxml/OOXMLRelationship.java)) with strict ZIP bomb defenses, traversal checks, and entity protections.
2. **Semantic Model Extraction (`DocumentParser`)**: Traverses post-CDR output documents to extract human-readable metadata, text blocks, images, hyperlinks, and layout structures for the final [`DocumentModel`](file:///d:/CAIR/DOC%20SHIELD/DocShield/cdr/src/main/java/model/common/DocumentModel.java) report.
3. **Sandboxed Legacy Conversion (`parsing.legacy`)**: Provides out-of-process conversion bridges from legacy binary formats (`DOC`, `PPT`, `XLS`) to modern OOXML.

---

## 2. Subpackage Map

```
parsing/
├── README.md                      # This architectural document
├── common/                        # Shared metadata extractors and ParserFactory
├── ooxml/                         # Secure OOXMLPackageReader (ZIP / XML / .rels)
├── docx/                          # DOCX semantic content parser
├── pptx/                          # PPTX semantic slide and layout parser
├── xlsx/                          # XLSX semantic sheet parser
├── doc/                           # Legacy DOC POI parser & DOCToDOCXConverter
├── ppt/                           # Legacy PPT POI parser & PPTToPPTXConverter
├── xls/                           # Legacy XLS POI parser & XLSToXLSXConverter
├── pdf/                           # PDFBox semantic parser
├── rtf/                           # RTF parser used by the RTF CDR pipeline
└── legacy/                        # Shared sandboxed LibreOffice conversion driver
```
