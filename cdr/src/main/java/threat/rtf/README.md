# RTF Threat Analyzer Subsystem (`threat.rtf`)

The `threat.rtf` package provides capability-based, non-executing security inspection for Rich Text Format (`.rtf`) documents.

---

## 1. Security Surface & Capability Coverage

RTF documents have historically been a prolific vector for targeted attacks and exploit delivery due to legacy compatibility features in Microsoft Word and RTF reader engines.

`RTFThreatAnalyzer` scans for the following security capabilities:

| Capability | Construct | Classification | Severity | Description |
|---|---|---|---|---|
| **Equation Editor Exploit** | `\object` with `\objclass Equation.3` or CLSID `{0002CE02-0000-0000-C000-000000000046}` | `THREAT` | `CRITICAL` | Weaponized stack-overflow exploits (CVE-2017-11882, CVE-2018-0802). |
| **Native Executable Drop** | `\objdata` containing PE / MZ headers (`0x4D 0x5A`) | `THREAT` | `CRITICAL` | Embedded Windows PE executable payload. |
| **Script Payload** | `\objdata` with `.vbs`, `.bat`, `.cmd`, `.ps1`, `.js` | `THREAT` | `CRITICAL` | Embedded script execution chains. |
| **Dynamic Data Exchange** | `\fldinst ... DDE` or `DDEAUTO` | `THREAT` | `CRITICAL` | Arbitrary command execution via Word DDE protocol. |
| **External Template Injection** | `\template` destination group | `THREAT` | `CRITICAL` | Forces Word to fetch and execute remote attached templates upon opening. |
| **Dangerous Hyperlink Scheme** | `HYPERLINK "file:..."`, `powershell:`, `ms-msdt:`, UNC | `THREAT` | `CRITICAL` | Protocol handler execution or NTLM hash exfiltration. |
| **VBA Macro Storage** | OLE Structured Storage with VBA streams in `\objdata` | `THREAT` | `HIGH` | Macro-bearing OLE container inside RTF. |
| **ActiveX Control** | `\objocx` | `THREAT` | `HIGH` | Embedded ActiveX control. |
| **Linked OLE Object** | `\objlink`, `\objautlink` | `THREAT` | `HIGH` | External OLE object linking. |
| **Generic Embedded Object** | `\object` with unverified binary payload | `THREAT` | `HIGH` | Active embedded binary object. |
| **Remote Resource Include** | `INCLUDETEXT`, `INCLUDEPICTURE` pointing to remote/UNC targets | `POLICY_VIOLATION` | `HIGH` | External document inclusion. |
| **Embedded Font** | `\fontemb` | `POLICY_VIOLATION` | `MEDIUM` | Vulnerability vector in font rendering engines. |
| **Group Brace Imbalance** | Unbalanced `{` and `}` | `POLICY_VIOLATION` | `HIGH` | Corrupted group hierarchy or parser evasion attempt. |
