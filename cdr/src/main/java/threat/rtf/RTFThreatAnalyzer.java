package threat.rtf;

import org.apache.poi.poifs.filesystem.DirectoryNode;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatSeverity;
import threat.common.ThreatType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Structural, non-executing capability-based security analyzer for Rich Text Format (RTF) documents.
 * Inspects for weaponized attack vectors such as embedded OLE payloads, Equation Editor exploits,
 * DDE/DDEAUTO command injection, external template injection, and dangerous hyperlink schemes.
 */
public final class RTFThreatAnalyzer {

    private static final Pattern DDE_FIELD_PATTERN = Pattern.compile(
            "\\\\fldinst[^{}\\\\]*?\\b(DDE|DDEAUTO)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern TEMPLATE_PATTERN = Pattern.compile(
            "\\{\\\\\\*?\\\\template\\s+([^{}]+)\\}",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern HYPERLINK_PATTERN = Pattern.compile(
            "\\\\fldinst\\s+HYPERLINK\\s+\"?([^\"\\r\\n{}]+)\"?",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INCLUDE_FIELD_PATTERN = Pattern.compile(
            "\\\\fldinst\\s+(INCLUDE|INCLUDETEXT|INCLUDEPICTURE)\\s+\"?([^\"\\r\\n{}]+)\"?",
            Pattern.CASE_INSENSITIVE
    );

    private static final String EQUATION_CLSID = "0002ce02-0000-0000-c000-000000000046";

    public List<SecurityFinding> analyze(Path file) throws IOException {
        if (!Files.exists(file) || !Files.isRegularFile(file)) {
            throw new IOException("RTF file does not exist or is not a regular file: " + file);
        }
        String rtf = Files.readString(file, StandardCharsets.ISO_8859_1);
        return analyze(rtf);
    }

    public List<SecurityFinding> analyze(String rtf) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (rtf == null || rtf.isEmpty()) {
            return findings;
        }

        // 1. Check brace balancing and structural integrity
        checkBraceIntegrity(rtf, findings);

        // 2. Check for External Template Injection
        checkTemplateInjection(rtf, findings);

        // 3. Check for Dynamic Data Exchange (DDE / DDEAUTO)
        checkDDE(rtf, findings);

        // 4. Check for Embedded Objects & OLE Payloads
        checkEmbeddedObjects(rtf, findings);

        // 5. Check for Dangerous Hyperlinks
        checkHyperlinks(rtf, findings);

        // 6. Check for Remote Include Fields (INCLUDETEXT / INCLUDEPICTURE)
        checkIncludeFields(rtf, findings);

        // 7. Check for Embedded Fonts / Suspicious Constructs
        checkSuspiciousConstructs(rtf, findings);

        return findings;
    }

    private void checkBraceIntegrity(String rtf, List<SecurityFinding> findings) {
        int depth = 0;
        boolean escaped = false;
        boolean underflow = false;

        for (int i = 0; i < rtf.length(); i++) {
            char c = rtf.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth < 0) {
                    underflow = true;
                }
            }
        }

        if (depth != 0 || underflow) {
            findings.add(new SecurityFinding(
                    FindingClassification.POLICY_VIOLATION,
                    ThreatType.SUSPICIOUS_ARCHIVE,
                    ThreatSeverity.HIGH,
                    null,
                    "rtf/group_structure",
                    null,
                    "Unbalanced RTF group brace structure (final depth: " + depth + ", underflow: " + underflow + ")",
                    "The RTF document contains malformed or mismatched brace groups capable of exploiting parser boundaries.",
                    "Normalize or quarantine the document with corrupted group hierarchy."
            ));
        }
    }

    private void checkTemplateInjection(String rtf, List<SecurityFinding> findings) {
        Matcher matcher = TEMPLATE_PATTERN.matcher(rtf);
        while (matcher.find()) {
            String target = matcher.group(1).trim();
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.EXTERNAL_TEMPLATE,
                    ThreatSeverity.CRITICAL,
                    null,
                    "rtf/template",
                    null,
                    "External template directive detected: " + target,
                    "RTF \\template destination causes Microsoft Word to fetch and execute remote attached templates upon opening.",
                    "Remove the \\template group during RTF sanitization."
            ));
        }
    }

    private void checkDDE(String rtf, List<SecurityFinding> findings) {
        Matcher matcher = DDE_FIELD_PATTERN.matcher(rtf);
        while (matcher.find()) {
            String token = matcher.group(1);
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.DDE,
                    ThreatSeverity.CRITICAL,
                    null,
                    "rtf/field/dde",
                    null,
                    "Dynamic Data Exchange construct detected (" + token.toUpperCase(Locale.ROOT) + ")",
                    "Word DDE fields can invoke operating system commands or communicate with external processes.",
                    "Disarm the DDE field instruction during RTF sanitization while retaining static display text."
            ));
        }
    }

    private void checkEmbeddedObjects(String rtf, List<SecurityFinding> findings) {
        int searchFrom = 0;
        int objectIndex = 1;

        while (true) {
            int start = findObjectGroupStart(rtf, searchFrom);
            if (start == -1) break;

            int end = findGroupEnd(rtf, start);
            if (end == -1) break;

            String group = rtf.substring(start, end + 1);
            analyzeObjectGroup(group, objectIndex, findings);

            objectIndex++;
            searchFrom = end + 1;
        }
    }

    private int findObjectGroupStart(String rtf, int searchFrom) {
        int idx = searchFrom;
        while (idx < rtf.length()) {
            int brace = rtf.indexOf('{', idx);
            if (brace == -1) return -1;

            int next = brace + 1;
            while (next < rtf.length() && Character.isWhitespace(rtf.charAt(next))) {
                next++;
            }
            if (next < rtf.length() && rtf.charAt(next) == '\\') {
                int afterSlash = next + 1;
                if (afterSlash < rtf.length() && rtf.charAt(afterSlash) == '*') {
                    afterSlash++;
                    while (afterSlash < rtf.length() && Character.isWhitespace(rtf.charAt(afterSlash))) {
                        afterSlash++;
                    }
                    if (afterSlash < rtf.length() && rtf.charAt(afterSlash) == '\\') {
                        afterSlash++;
                    }
                }
                if (rtf.startsWith("object", afterSlash)) {
                    return brace;
                }
            }
            idx = brace + 1;
        }
        return -1;
    }

    private void analyzeObjectGroup(String group, int index, List<SecurityFinding> findings) {
        String objClass = extractControlValue(group, "\\objclass");
        String objName = extractControlValue(group, "\\objname");
        String oleClsid = extractControlValue(group, "\\oleclsid");
        boolean isOcx = group.contains("\\objocx");
        boolean isLinked = group.contains("\\objlink") || group.contains("\\objautlink");

        String location = "rtf_object_" + index;
        String descClass = (objClass != null ? objClass : "UnknownClass");

        // Check Equation Editor exploits (CVE-2017-11882 / CVE-2018-0802)
        if (isEquationEditor(descClass, oleClsid, group)) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.EMBEDDED_ACTIVE_CONTENT,
                    ThreatSeverity.CRITICAL,
                    null,
                    location,
                    null,
                    "Equation Editor embedded object construct detected (" + descClass + ")",
                    "Equation Editor OLE objects (CVE-2017-11882 / CVE-2018-0802) represent weaponized buffer-overflow execution vectors.",
                    "Strip the embedded OLE object during RTF reconstruction."
            ));
            return;
        }

        // Check ActiveX controls
        if (isOcx) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.ACTIVEX_OBJECT,
                    ThreatSeverity.HIGH,
                    null,
                    location,
                    null,
                    "Embedded ActiveX control detected (\\objocx) at " + location,
                    "ActiveX controls inside RTF can invoke COM controls and execute unsafe scriptable methods.",
                    "Disarm and strip ActiveX control group."
            ));
        }

        // Check OLE linking
        if (isLinked) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.EXTERNAL_REFERENCE,
                    ThreatSeverity.HIGH,
                    null,
                    location,
                    null,
                    "Linked OLE object detected (\\objlink/\\objautlink) at " + location,
                    "Linked OLE objects reference external resources and can trigger unexpected network connections or payload downloads.",
                    "Disarm external OLE links during RTF reconstruction."
            ));
        }

        // Inspect raw objdata bytes
        String hexData = extractObjData(group);
        if (hexData != null && !hexData.isEmpty()) {
            byte[] data = decodeHex(hexData);
            if (data.length == 0) {
                findings.add(new SecurityFinding(
                        FindingClassification.SUSPICIOUS,
                        ThreatType.SUSPICIOUS_BINARY,
                        ThreatSeverity.HIGH,
                        null,
                        location,
                        null,
                        "Corrupted or malformed hex-encoded \\objdata at " + location,
                        "The embedded object contains non-decodable or invalid hex stream data.",
                        "Strip corrupted object data."
                ));
                return;
            }

            // Inspect decoded binary for executable / script payloads
            inspectDecodedObjData(data, location, descClass, findings);
        } else {
            // Embedded object with no objdata or unparseable stream
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.EMBEDDED_OBJECT,
                    ThreatSeverity.HIGH,
                    null,
                    location,
                    null,
                    "Generic embedded object detected at " + location + " (class: " + descClass + ")",
                    "Unverified embedded objects in RTF pose active payload delivery and exploit risks.",
                    "Remove embedded object construct."
            ));
        }
    }

    private boolean isEquationEditor(String objClass, String oleClsid, String group) {
        String lowerClass = objClass.toLowerCase(Locale.ROOT);
        if (lowerClass.contains("equation") || lowerClass.contains("eqnedt")) {
            return true;
        }
        if (oleClsid != null && oleClsid.toLowerCase(Locale.ROOT).contains(EQUATION_CLSID)) {
            return true;
        }
        return group.toLowerCase(Locale.ROOT).contains(EQUATION_CLSID);
    }

    private void inspectDecodedObjData(byte[] data, String location, String objClass, List<SecurityFinding> findings) {
        // 1. Check for standalone PE executable (MZ header and PE signature)
        if (containsPeExecutable(data)) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.EXECUTABLE_PAYLOAD,
                    ThreatSeverity.CRITICAL,
                    null,
                    location,
                    null,
                    "Embedded Windows executable (PE/MZ) binary detected in \\objdata at " + location,
                    "The embedded object contains a native executable payload.",
                    "Disarm and remove embedded executable."
            ));
            return;
        }

        // 2. Check for script content inside OLE/Ole10Native stream
        if (containsScriptPayload(data)) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.SCRIPT_CONTENT,
                    ThreatSeverity.CRITICAL,
                    null,
                    location,
                    null,
                    "Script-bearing payload detected in embedded object \\objdata at " + location,
                    "The object stream contains script or batch command execution directives.",
                    "Disarm and strip embedded script."
            ));
            return;
        }

        // 3. Check for OLE Structured Storage (D0 CF 11 E0 A1 B1 1A E1)
        if (isOleHeader(data)) {
            inspectOleContainer(data, location, objClass, findings);
            return;
        }

        // 4. Default: Embedded object present
        findings.add(new SecurityFinding(
                FindingClassification.THREAT,
                ThreatType.EMBEDDED_OBJECT,
                ThreatSeverity.HIGH,
                null,
                location,
                null,
                "Embedded binary object payload (class: " + objClass + ") at " + location,
                "The RTF document contains an embedded binary object requiring disarming.",
                "Remove embedded object during RTF reconstruction."
        ));
    }

    private boolean containsPeExecutable(byte[] data) {
        if (data.length < 64) return false;
        // Check for MZ header: 0x4D 0x5A
        for (int i = 0; i <= data.length - 64; i++) {
            if (data[i] == 0x4D && data[i + 1] == 0x5A) {
                // e_lfanew at offset 0x3C
                int lfanewOffset = i + 0x3C;
                if (lfanewOffset + 4 <= data.length) {
                    int peOffset = (data[lfanewOffset] & 0xFF)
                            | ((data[lfanewOffset + 1] & 0xFF) << 8)
                            | ((data[lfanewOffset + 2] & 0xFF) << 16)
                            | ((data[lfanewOffset + 3] & 0xFF) << 24);
                    if (peOffset > 0 && i + peOffset + 4 <= data.length) {
                        int pos = i + peOffset;
                        if (data[pos] == 0x50 && data[pos + 1] == 0x45 && data[pos + 2] == 0x00 && data[pos + 3] == 0x00) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean containsScriptPayload(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
        return text.contains(".bat\0") || text.contains(".cmd\0") || text.contains(".vbs\0")
                || text.contains(".ps1\0") || text.contains(".js\0") || text.contains(".exe\0")
                || text.contains("wscript.shell") || text.contains("powershell")
                || text.contains("cmd.exe /c");
    }

    private boolean isOleHeader(byte[] data) {
        return data.length >= 8
                && (data[0] & 0xFF) == 0xD0 && (data[1] & 0xFF) == 0xCF
                && (data[2] & 0xFF) == 0x11 && (data[3] & 0xFF) == 0xE0
                && (data[4] & 0xFF) == 0xA1 && (data[5] & 0xFF) == 0xB1
                && (data[6] & 0xFF) == 0x1A && (data[7] & 0xFF) == 0xE1;
    }

    private void inspectOleContainer(byte[] data, String location, String objClass, List<SecurityFinding> findings) {
        boolean hasMacros = false;
        try (POIFSFileSystem fs = new POIFSFileSystem(new ByteArrayInputStream(data))) {
            hasMacros = hasVbaStorage(fs.getRoot(), "");
        } catch (Exception ignored) {
            // Not a strict POIFS filesystem; fallback to raw byte inspection
            String raw = new String(data, StandardCharsets.ISO_8859_1).toLowerCase(Locale.ROOT);
            hasMacros = raw.contains("vba") || raw.contains("_vba_project") || raw.contains("macros");
        }

        if (hasMacros) {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.VBA_PROJECT,
                    ThreatSeverity.HIGH,
                    null,
                    location,
                    null,
                    "VBA macro project storage detected in embedded OLE object at " + location,
                    "The embedded OLE storage contains macro streams capable of executing arbitrary code.",
                    "Strip macro-bearing OLE container during RTF reconstruction."
            ));
        } else {
            findings.add(new SecurityFinding(
                    FindingClassification.THREAT,
                    ThreatType.OLE_OBJECT,
                    ThreatSeverity.HIGH,
                    null,
                    location,
                    null,
                    "Embedded OLE Structured Storage container (class: " + objClass + ") at " + location,
                    "Active OLE compound document container present in RTF.",
                    "Strip embedded OLE container during RTF reconstruction."
            ));
        }
    }

    private boolean hasVbaStorage(DirectoryNode dir, String parent) {
        for (Entry entry : dir) {
            if (entry == null) continue;
            String name = entry.getName().toLowerCase(Locale.ROOT);
            if (name.contains("vba") || name.contains("macro") || name.equals("_vba_project") || name.equals("dir")) {
                return true;
            }
            if (entry instanceof DirectoryNode child) {
                if (hasVbaStorage(child, parent + "/" + name)) {
                    return true;
                }
            }
        }
        return false;
    }

    private void checkHyperlinks(String rtf, List<SecurityFinding> findings) {
        Matcher matcher = HYPERLINK_PATTERN.matcher(rtf);
        while (matcher.find()) {
            String target = matcher.group(1).trim();
            if (isDangerousUri(target)) {
                findings.add(new SecurityFinding(
                        FindingClassification.THREAT,
                        ThreatType.DANGEROUS_URI,
                        ThreatSeverity.CRITICAL,
                        null,
                        "rtf/hyperlink",
                        null,
                        "Dangerous URI scheme in RTF hyperlink: " + target,
                        "Hyperlinks referencing application, file, or script schemes can achieve code execution when clicked.",
                        "Neutralize dangerous hyperlink target."
                ));
            }
        }
    }

    private boolean isDangerousUri(String uri) {
        if (uri == null || uri.isBlank()) return false;
        String lower = uri.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("file:")
                || lower.startsWith("powershell:")
                || lower.startsWith("powershell")
                || lower.startsWith("cmd:")
                || lower.startsWith("cmd.exe")
                || lower.startsWith("cmd ")
                || lower.startsWith("ms-msdt:")
                || lower.startsWith("search-ms:")
                || lower.startsWith("javascript:")
                || lower.startsWith("vbscript:")
                || lower.startsWith("cpl:")
                || lower.startsWith("reg:")
                || lower.startsWith("wsf:")
                || lower.startsWith("shell:")
                || lower.startsWith("calc:")
                || lower.startsWith("rundll32")
                || lower.startsWith("\\\\")
                || lower.contains(".exe")
                || lower.contains(".bat")
                || lower.contains(".cmd")
                || lower.contains(".vbs")
                || lower.contains(".ps1");
    }

    private void checkIncludeFields(String rtf, List<SecurityFinding> findings) {
        Matcher matcher = INCLUDE_FIELD_PATTERN.matcher(rtf);
        while (matcher.find()) {
            String fieldType = matcher.group(1);
            String target = matcher.group(2).trim();
            String lower = target.toLowerCase(Locale.ROOT);
            if (lower.startsWith("http:") || lower.startsWith("https:") || lower.startsWith("\\\\") || lower.startsWith("file:")) {
                findings.add(new SecurityFinding(
                        FindingClassification.POLICY_VIOLATION,
                        ThreatType.EXTERNAL_RESOURCE,
                        ThreatSeverity.HIGH,
                        null,
                        "rtf/field/" + fieldType.toLowerCase(Locale.ROOT),
                        null,
                        "External resource reference in RTF " + fieldType + " field: " + target,
                        "External include fields fetch content from remote or network targets when opened.",
                        "Strip external include field directive while preserving static display text."
                ));
            }
        }
    }

    private void checkSuspiciousConstructs(String rtf, List<SecurityFinding> findings) {
        if (rtf.contains("\\fontemb")) {
            findings.add(new SecurityFinding(
                    FindingClassification.POLICY_VIOLATION,
                    ThreatType.SUSPICIOUS_BINARY,
                    ThreatSeverity.MEDIUM,
                    null,
                    "rtf/fontemb",
                    null,
                    "Embedded font construct detected (\\fontemb)",
                    "Embedded fonts can exploit vulnerabilities in font parsing engines.",
                    "Strip embedded font construct."
            ));
        }
    }

    // =========================================================
    // HELPER METHODS
    // =========================================================

    private int findGroupEnd(String rtf, int start) {
        int depth = 0;
        boolean escaped = false;
        for (int i = start; i < rtf.length(); i++) {
            char c = rtf.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '{') {
                depth++;
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private String extractControlValue(String group, String controlWord) {
        int start = group.indexOf(controlWord);
        if (start == -1) return null;

        start += controlWord.length();
        while (start < group.length() && Character.isWhitespace(group.charAt(start))) {
            start++;
        }

        StringBuilder value = new StringBuilder();
        for (int i = start; i < group.length(); i++) {
            char c = group.charAt(i);
            if (Character.isWhitespace(c) || c == '\\' || c == '{' || c == '}') {
                break;
            }
            value.append(c);
        }
        return value.length() > 0 ? value.toString() : null;
    }

    private String extractObjData(String group) {
        int marker = group.indexOf("\\objdata");
        if (marker == -1) return null;

        int start = marker + "\\objdata".length();
        StringBuilder hex = new StringBuilder();
        for (int i = start; i < group.length(); i++) {
            char c = group.charAt(i);
            if (isHexCharacter(c)) {
                hex.append(c);
            }
        }
        return hex.toString();
    }

    private boolean isHexCharacter(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private byte[] decodeHex(String hex) {
        int length = hex.length() / 2;
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) return new byte[0];
            data[i] = (byte) ((high << 4) | low);
        }
        return data;
    }
}
