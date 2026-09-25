package sanitization.rtf;

import threat.common.SecurityFinding;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RTF Threat Sanitizer.
 * Performs surgical, group-aware disarming of embedded OLE objects, Equation Editor exploits,
 * DDE/DDEAUTO fields, external templates, and dangerous URI handlers in Rich Text Format documents.
 */
public final class RTFThreatSanitizer {

    private static final Pattern TEMPLATE_PATTERN = Pattern.compile(
            "\\{\\\\\\*?\\\\template\\s+([^{}]+)\\}",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern DDE_TOKEN = Pattern.compile(
            "\\b(DDE|DDEAUTO)\\b",
            Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INCLUDE_TOKEN = Pattern.compile(
            "\\b(INCLUDE|INCLUDETEXT|INCLUDEPICTURE)\\s+\"?([^\"\\r\\n{}]+)\"?",
            Pattern.CASE_INSENSITIVE
    );

    public static class SanitizationResult {
        private final String sanitizedRtf;
        private final List<String> actions;

        public SanitizationResult(String sanitizedRtf, List<String> actions) {
            this.sanitizedRtf = sanitizedRtf;
            this.actions = actions != null ? actions : Collections.emptyList();
        }

        public String getSanitizedRtf() {
            return sanitizedRtf;
        }

        public List<String> getActions() {
            return actions;
        }
    }

    public SanitizationResult sanitize(String rtf, List<SecurityFinding> findings) {
        if (rtf == null || rtf.isEmpty()) {
            return new SanitizationResult(rtf, Collections.emptyList());
        }

        List<ReplacementChunk> chunks = new ArrayList<>();
        List<String> actions = new ArrayList<>();

        // 1. Template injection disarming
        disarmTemplates(rtf, chunks, actions);

        // 2. Embedded objects disarming
        disarmEmbeddedObjects(rtf, chunks, actions);

        // 3. Fields disarming (DDE, remote includes, dangerous hyperlinks)
        disarmFields(rtf, chunks, actions);

        // 4. Embedded fonts and active controls
        disarmSuspiciousControls(rtf, chunks, actions);

        // Sort chunks in descending order of startIndex so replacements do not shift offsets
        chunks.sort(Comparator.comparingInt(ReplacementChunk::start).reversed());

        // Apply non-overlapping replacements
        StringBuilder sb = new StringBuilder(rtf);
        int lastStart = Integer.MAX_VALUE;

        for (ReplacementChunk chunk : chunks) {
            if (chunk.end() <= lastStart && chunk.start() < chunk.end() && chunk.end() <= sb.length()) {
                sb.replace(chunk.start(), chunk.end(), chunk.replacement());
                lastStart = chunk.start();
            }
        }

        String result = sb.toString();
        return new SanitizationResult(result, actions);
    }

    public List<String> sanitize(Path inputFile, Path outputFile, List<SecurityFinding> findings) throws IOException {
        String rtf = Files.readString(inputFile, StandardCharsets.ISO_8859_1);
        SanitizationResult result = sanitize(rtf, findings);
        Files.writeString(outputFile, result.getSanitizedRtf(), StandardCharsets.ISO_8859_1);
        return result.getActions();
    }

    // =========================================================
    // DISARMING IMPLEMENTATIONS
    // =========================================================

    private void disarmTemplates(String rtf, List<ReplacementChunk> chunks, List<String> actions) {
        Matcher matcher = TEMPLATE_PATTERN.matcher(rtf);
        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            String target = matcher.group(1).trim();
            chunks.add(new ReplacementChunk(start, end, ""));
            actions.add("Removed external template injection directive: " + target);
        }
    }

    private void disarmEmbeddedObjects(String rtf, List<ReplacementChunk> chunks, List<String> actions) {
        int searchFrom = 0;
        int objectIndex = 1;

        while (true) {
            int start = findObjectGroupStart(rtf, searchFrom);
            if (start == -1) break;

            int end = findGroupEnd(rtf, start);
            if (end == -1) break;

            String group = rtf.substring(start, end + 1);
            String objClass = extractControlValue(group, "\\objclass");
            String objName = extractControlValue(group, "\\objname");
            String desc = (objClass != null ? objClass : (objName != null ? objName : "rtf_object_" + objectIndex));

            // Check if group contains a benign static picture in \result group
            String replacement = extractStaticPicture(group);
            chunks.add(new ReplacementChunk(start, end + 1, replacement));
            if (!replacement.isEmpty()) {
                actions.add("Disarmed embedded object (" + desc + "); preserved benign static preview picture.");
            } else {
                actions.add("Disarmed and removed embedded object: " + desc);
            }

            objectIndex++;
            searchFrom = end + 1;
        }
    }

    private String extractStaticPicture(String group) {
        int resultIdx = group.indexOf("\\result");
        if (resultIdx != -1) {
            int pictIdx = group.indexOf("{\\pict", resultIdx);
            if (pictIdx != -1) {
                int pictEnd = findGroupEnd(group, pictIdx);
                if (pictEnd != -1) {
                    return group.substring(pictIdx, pictEnd + 1);
                }
            }
        }
        return "";
    }

    private void disarmFields(String rtf, List<ReplacementChunk> chunks, List<String> actions) {
        int searchFrom = 0;
        while (true) {
            int start = findFieldGroupStart(rtf, searchFrom);
            if (start == -1) break;

            int end = findGroupEnd(rtf, start);
            if (end == -1) break;

            String group = rtf.substring(start, end + 1);
            disarmSingleField(group, start, end, chunks, actions);

            searchFrom = end + 1;
        }
    }

    private void disarmSingleField(String group, int start, int end,
                                   List<ReplacementChunk> chunks, List<String> actions) {
        // 1. DDE / DDEAUTO check
        if (DDE_TOKEN.matcher(group).find()) {
            String cachedText = extractFieldResultText(group);
            chunks.add(new ReplacementChunk(start, end + 1, cachedText));
            actions.add("Disarmed DDE/DDEAUTO command execution field; retained static text.");
            return;
        }

        // 2. Remote include check (INCLUDETEXT / INCLUDEPICTURE)
        Matcher includeMatcher = INCLUDE_TOKEN.matcher(group);
        if (includeMatcher.find()) {
            String target = includeMatcher.group(2).trim();
            String lower = target.toLowerCase(Locale.ROOT);
            if (lower.startsWith("http:") || lower.startsWith("https:") || lower.startsWith("\\\\") || lower.startsWith("file:")) {
                String cachedText = extractFieldResultText(group);
                chunks.add(new ReplacementChunk(start, end + 1, cachedText));
                actions.add("Disarmed remote include field referencing " + target + "; retained static text.");
                return;
            }
        }

        // 3. Dangerous Hyperlink check
        int hlIdx = group.indexOf("HYPERLINK");
        if (hlIdx != -1) {
            int targetStart = hlIdx + "HYPERLINK".length();
            while (targetStart < group.length() && Character.isWhitespace(group.charAt(targetStart))) {
                targetStart++;
            }
            if (targetStart < group.length()) {
                String uri = extractUriToken(group, targetStart);
                if (isDangerousUri(uri)) {
                    // Replace dangerous URI with safe disarmed anchor #disarmed
                    int uriOffsetInGroup = group.indexOf(uri, targetStart);
                    if (uriOffsetInGroup != -1) {
                        int globalStart = start + uriOffsetInGroup;
                        int globalEnd = globalStart + uri.length();
                        chunks.add(new ReplacementChunk(globalStart, globalEnd, "#disarmed"));
                        actions.add("Neutralized dangerous hyperlink target: " + uri);
                        return;
                    }
                }
            }
        }
    }

    private String extractUriToken(String s, int start) {
        StringBuilder sb = new StringBuilder();
        boolean inQuotes = false;
        if (start < s.length() && (s.charAt(start) == '"' || s.charAt(start) == '\'')) {
            inQuotes = true;
            start++;
        }
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inQuotes) {
                if (c == '"' || c == '\'') break;
                sb.append(c);
            } else {
                if (Character.isWhitespace(c) || c == '}' || c == '{' || c == '\\') break;
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private String extractFieldResultText(String fieldGroup) {
        int rsltIdx = fieldGroup.indexOf("\\fldrslt");
        if (rsltIdx == -1) return "";

        int start = rsltIdx + "\\fldrslt".length();
        while (start < fieldGroup.length() && Character.isWhitespace(fieldGroup.charAt(start))) {
            start++;
        }

        // Look for group or plain text inside
        if (start < fieldGroup.length() && fieldGroup.charAt(start) == '{') {
            int end = findGroupEnd(fieldGroup, start);
            if (end != -1) {
                return fieldGroup.substring(start, end + 1);
            }
        }

        // Otherwise extract up to preceding closing brace of \field
        int end = fieldGroup.lastIndexOf('}');
        if (end > start) {
            return fieldGroup.substring(start, end).trim();
        }
        return "";
    }

    private void disarmSuspiciousControls(String rtf, List<ReplacementChunk> chunks, List<String> actions) {
        // Disarm \fontemb groups
        int idx = 0;
        while (true) {
            int start = rtf.indexOf("{\\fontemb", idx);
            if (start == -1) break;
            int end = findGroupEnd(rtf, start);
            if (end == -1) break;
            chunks.add(new ReplacementChunk(start, end + 1, ""));
            actions.add("Removed embedded font construct (\\fontemb).");
            idx = end + 1;
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

    // =========================================================
    // GROUP SCANNING UTILITIES
    // =========================================================

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

    private int findFieldGroupStart(String rtf, int searchFrom) {
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
                if (rtf.startsWith("field", afterSlash)) {
                    return brace;
                }
            }
            idx = brace + 1;
        }
        return -1;
    }

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

    private record ReplacementChunk(int start, int end, String replacement) { }
}
