package processing.rtf;

import processing.common.CDRConsoleReporter;
import processing.common.CDRFileUtil;
import processing.common.CDRProcessor;
import processing.common.CDRResult;
import sanitization.rtf.RTFThreatSanitizer;
import threat.common.FindingClassification;
import threat.common.SecurityFinding;
import threat.rtf.RTFThreatAnalyzer;
import validation.rtf.RTFIntegrityValidator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * RTF Content Disarm and Reconstruction (CDR) processor.
 * Analyzes untrusted Rich Text Format files for capabilities and threats,
 * copies clean inputs byte-for-byte with SHA-256 verification, and executes
 * surgical sanitization and post-reconstruction integrity validation for weaponized files.
 */
public final class RTFCDRProcessor implements CDRProcessor {

    @Override
    public CDRResult process(Path inputFile, Path outputFile) throws Exception {
        return process(inputFile, outputFile, true);
    }

    public CDRResult process(Path inputFile, Path outputFile, boolean printConsoleFindings) throws Exception {
        if (!Files.exists(inputFile) || !Files.isRegularFile(inputFile)) {
            throw new IOException("RTF input is not a readable regular file: " + inputFile);
        }

        final String inputSha256 = CDRFileUtil.sha256(inputFile);
        RTFThreatAnalyzer analyzer = new RTFThreatAnalyzer();
        List<SecurityFinding> findings = analyzer.analyze(inputFile);

        if (printConsoleFindings) {
            CDRConsoleReporter.printAnalyzerFindings("RTF", findings);
        }

        // Clean document fast-path: preserve byte-for-byte identity
        if (!containsBlockingFinding(findings)) {
            CDRFileUtil.copyOriginal(inputFile, outputFile);
            String outputSha256 = CDRFileUtil.sha256(outputFile);
            if (!inputSha256.equals(outputSha256)) {
                throw new IOException("Clean RTF copy failed byte-for-byte SHA-256 identity verification.");
            }
            List<String> actions = new ArrayList<>();
            actions.add("Input verified clean; original RTF copied without reconstruction.");
            return new CDRResult(findings, actions, outputFile, false, true, true,
                    new ArrayList<>(), inputSha256, outputSha256, true);
        }

        // Threat or policy violation present: execute sanitization and reconstruction
        RTFThreatSanitizer sanitizer = new RTFThreatSanitizer();
        Path normalizedOutput = outputFile.toAbsolutePath().normalize();
        Path parent = normalizedOutput.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path tempOutput = Files.createTempFile(parent == null ? Path.of(".") : parent, ".docshield-rtf-", ".tmp");
        List<String> actions = new ArrayList<>();

        try {
            actions.addAll(sanitizer.sanitize(inputFile, tempOutput, findings));
            try {
                Files.move(tempOutput, normalizedOutput,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (Exception ex) {
                Files.move(tempOutput, normalizedOutput,
                        StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tempOutput);
        }

        boolean reconstructed = Files.exists(outputFile) && Files.size(outputFile) > 0;
        boolean integrityPassed = false;
        boolean threatsRemoved = false;
        List<SecurityFinding> finalFindings = new ArrayList<>();
        RTFIntegrityValidator validator = new RTFIntegrityValidator();

        // Bounded post-reconstruction validation loop (at most 3 passes)
        for (int pass = 1; reconstructed && pass <= 3; pass++) {
            integrityPassed = validator.validate(outputFile);
            finalFindings = new ArrayList<>(analyzer.analyze(outputFile));
            threatsRemoved = integrityPassed && !containsBlockingFinding(finalFindings);

            if (threatsRemoved) {
                break;
            }

            if (pass < 3 && containsBlockingFinding(finalFindings)) {
                Path retryTemp = Files.createTempFile(parent == null ? Path.of(".") : parent, ".docshield-rtf-retry-", ".tmp");
                try {
                    List<String> retryActions = sanitizer.sanitize(outputFile, retryTemp, finalFindings);
                    actions.addAll(retryActions);
                    Files.move(retryTemp, normalizedOutput, StandardCopyOption.REPLACE_EXISTING);
                } finally {
                    Files.deleteIfExists(retryTemp);
                }
            }
        }

        if (printConsoleFindings) {
            CDRConsoleReporter.printFinalFindings("RTF", finalFindings);
        }

        if (!finalFindings.isEmpty()) {
            actions.add("Post-reconstruction security verification found remaining blocking or policy findings.");
        }

        String outputSha256 = reconstructed ? CDRFileUtil.sha256(outputFile) : null;
        return new CDRResult(findings, actions, outputFile, reconstructed,
                integrityPassed, threatsRemoved, finalFindings, inputSha256, outputSha256, false);
    }

    private boolean containsBlockingFinding(List<SecurityFinding> findings) {
        if (findings == null) return false;
        for (SecurityFinding finding : findings) {
            if (finding != null &&
                    (finding.getClassification() == FindingClassification.THREAT
                    || finding.getClassification() == FindingClassification.POLICY_VIOLATION
                    || finding.getClassification() == FindingClassification.SUSPICIOUS)) {
                return true;
            }
        }
        return false;
    }
}
