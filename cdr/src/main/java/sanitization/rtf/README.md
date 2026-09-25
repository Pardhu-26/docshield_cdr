# RTF Threat Sanitizer Subsystem (`sanitization.rtf`)

The `sanitization.rtf` package provides surgical disarming and sanitization for Rich Text Format (`.rtf`) documents.

---

## 1. Disarming Strategy

DocShield employs zero-trust disarming on RTF documents:

1. **Embedded Objects (`\object`)**:
   - Weaponized or unverified embedded OLE objects (Equation Editor CVE-2017-11882/0802, ActiveX controls, dropped native executables, macro-bearing storages) are surgically excised from the document stream.
   - If an object group contains a benign static preview picture (`\result` group with `\pict`), the preview picture is preserved so the visual fidelity of the reconstructed document is retained while all active execution capabilities are neutralized.
2. **Dynamic Data Exchange (`DDE` / `DDEAUTO`)**:
   - Field instructions containing DDE/DDEAUTO execution commands are stripped.
   - If a cached result (`\fldrslt`) is present, the static display text is unwrapped and preserved.
3. **External Templates (`\template`)**:
   - The entire `\template` destination group referencing remote shares or URLs is cleanly removed.
4. **Dangerous Hyperlinks**:
   - Dangerous URI schemes (`file:`, `powershell:`, `ms-msdt:`, `search-ms:`, `javascript:`, UNC paths, etc.) have their targets neutralized to `#disarmed` to prevent client-side protocol handler execution while preserving surrounding document layout.
5. **Remote Include Fields**:
   - Remote `INCLUDETEXT` and `INCLUDEPICTURE` fields referencing network locations are stripped, preserving cached display text if available.
