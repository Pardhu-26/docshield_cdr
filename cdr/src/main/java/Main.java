import identification.FileIdentifier;
import identification.FileInfo;
import identification.Format;

import model.common.DocumentModel;

import parsing.common.DocumentParser;
import parsing.common.ParserFactory;

import processing.common.CDRProcessor;
import processing.common.CDRResult;
import processing.doc.DOCCDRProcessor;
import processing.ppt.PPTCDRProcessor;
import processing.xls.XLSCDRProcessor;
import processing.docx.DOCXCDRProcessor;
import processing.pptx.PPTXCDRProcessor;
import processing.xlsx.XLSXCDRProcessor;
import processing.pdf.PDFCDRProcessor;
import processing.rtf.RTFCDRProcessor;

import reporting.ReportWriter;
import application.UserFacingError;
import security.QuarantineManager;

import java.nio.file.Files;
import java.io.IOException;

import java.nio.file.Path;

public class Main {

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("DocShield: Please provide an input file and an output file.");
            System.out.println("Usage: ./scripts/sandbox-run.sh <input-file> <output-file>");
            System.exit(1);
        }

        final Path inputFile;
        final Path outputFile;
        try {
            inputFile = Path.of(args[0]).toAbsolutePath().normalize();
            outputFile = Path.of(args[1]).toAbsolutePath().normalize();
        } catch (Exception e) {
            System.out.println("DocShield: The file path provided is invalid.");
            System.exit(1);
            return;
        }

        if (inputFile.equals(outputFile)) {
            System.out.println("DocShield: Input and output files must be different.");
            System.out.println("No changes were made to the input file.");
            System.exit(1);
        }

        if (!Files.exists(inputFile)) {
            System.out.println("DocShield: File doesn't exist: " + inputFile);
            System.exit(1);
        }
        if (!Files.isRegularFile(inputFile)) {
            System.out.println("DocShield: The input path is not a file.");
            System.exit(1);
        }
        if (!Files.isReadable(inputFile)) {
            System.out.println("DocShield: The input file cannot be read. Check its permissions.");
            System.exit(1);
        }
        try {
            if (Files.size(inputFile) == 0) {
                quarantineAndExit(inputFile, "The input file is empty.",
                        "The file is empty and has been quarantined.");
            }
        } catch (IOException e) {
            System.out.println("DocShield: The input file could not be read.");
            System.exit(1);
        }

        FileInfo fileInfo;
        try {
            fileInfo = new FileIdentifier().identify(inputFile);
        } catch (Exception e) {
            quarantineAndExit(inputFile,
                    UserFacingError.message(e, inputFile, outputFile),
                    "The file could not be safely identified and has been quarantined.");
            return;
        }

        if (fileInfo.getFormat() == Format.UNKNOWN) {
            quarantineAndExit(inputFile,
                    "Unknown or unsupported file format.",
                    "Unknown file type — file has been quarantined.");
            return;
        }

        if (!fileInfo.isExtensionMatch()) {
            quarantineAndExit(inputFile,
                    "File extension does not match the detected file format.",
                    "File type mismatch — file has been quarantined.");
            return;
        }

        try {
            CDRProcessor processor = createProcessor(fileInfo);

            if (processor != null) {
                // Output-path errors are operator errors, not input-file threats.
                // Do not quarantine a perfectly valid input merely because the
                // destination cannot be written.
                try {
                    ensureOutputCanBeUsed(outputFile);
                } catch (Exception outputError) {
                    System.out.println("DocShield: " + UserFacingError.outputMessage(outputError, outputFile));
                    System.exit(1);
                }

                CDRResult result;
                try {
                    result = processor.process(inputFile, outputFile);
                } catch (Exception processingError) {
                    safeDelete(outputFile);
                    quarantineAndExit(inputFile,
                            UserFacingError.message(processingError, inputFile, outputFile),
                            "The file could not be processed safely — file has been quarantined.");
                    return;
                }

                if (!result.isOutputReady()) {
                    safeDelete(outputFile);
                    quarantineAndExit(inputFile,
                            "Processing did not produce a valid output file.",
                            "The file could not be safely released — file has been quarantined.");
                    return;
                }

                if (!result.isIntegrityPassed()) {
                    safeDelete(outputFile);
                    quarantineAndExit(inputFile,
                            "Post-reconstruction integrity validation failed.",
                            "The reconstructed file failed integrity validation — file has been quarantined.");
                    return;
                }

                if (result.hasBlockingFindings() && !result.isThreatRemoved()) {
                    safeDelete(outputFile);
                    quarantineAndExit(inputFile,
                            "A detected threat could not be completely removed.",
                            "Threat could not be safely removed — file has been quarantined.");
                    return;
                }

                // The reconstructed file has already passed CDR integrity checks.
                // A semantic-reporting failure must not destroy that valid output.
                try {
                    Format reportFormat = switch (fileInfo.getFormat()) {
                        case DOC -> Format.DOCX;
                        case PPT -> Format.PPTX;
                        case XLS -> Format.XLSX;
                        default -> fileInfo.getFormat();
                    };
                    DocumentParser parser = ParserFactory.getParser(reportFormat);
                    DocumentModel model = parser.parse(outputFile);
                    model.setFileInfo(fileInfo);
                    new ReportWriter().write(model, inputFile, result);
                } catch (Exception reportError) {
                    System.out.println("DocShield: The sanitized file was created successfully, but its detailed report could not be generated.");
                    System.out.println("Output: " + outputFile);
                    printSummary(inputFile, outputFile, result);
                    return;
                }

                printSummary(inputFile, outputFile, result);
                return;
            }

            // Non-OOXML formats retain the existing analysis path.
            DocumentParser parser = ParserFactory.getParser(fileInfo.getFormat());
            DocumentModel model = parser.parse(inputFile);
            model.setFileInfo(fileInfo);
            new ReportWriter().write(model, inputFile);
            System.out.println("DocShield: Analysis completed successfully.");
            System.out.println("Report: output/reports/" + inputFile.getFileName() + "_CDR_Report.txt");

        } catch (Exception e) {
            safeDelete(outputFile);
            String message = UserFacingError.message(e, inputFile, outputFile);
            quarantineAndExit(inputFile, message,
                    "Processing could not be completed safely — file has been quarantined.");
        }
    }

    private static void ensureOutputCanBeUsed(Path outputFile) throws IOException {
        if (outputFile.getParent() != null) {
            Files.createDirectories(outputFile.getParent());
        }
        if (Files.exists(outputFile) && !Files.isRegularFile(outputFile)) {
            throw new IOException("Output path is not a regular file.");
        }
        if (Files.exists(outputFile) && !Files.isWritable(outputFile)) {
            throw new IOException("Output file is not writable.");
        }
        Path parent = outputFile.getParent();
        if (parent != null && !Files.isWritable(parent)) {
            throw new IOException("Output directory is not writable.");
        }
    }

    private static void safeDelete(Path file) {
        try {
            if (file != null) Files.deleteIfExists(file);
        } catch (IOException cleanupError) {
            System.out.println("DocShield: A partial output file could not be removed. Please delete it manually: " + file);
            System.out.println("Cleanup reason: " + cleanupError.getMessage());
        }
    }

    private static void quarantineAndExit(Path inputFile, String reason, String resultMessage) {
        try {
            Path quarantined = QuarantineManager.quarantine(inputFile, reason);
            System.out.println("DocShield: " + resultMessage);
            System.out.println("Reason: " + reason);
            System.out.println("Quarantine: " + quarantined);
            System.exit(2);
        } catch (IOException quarantineError) {
            System.out.println("DocShield: " + resultMessage);
            System.out.println("Reason: " + reason);
            System.out.println("WARNING: The quarantine copy could not be created. Keep the original file isolated and do not open it.");
            System.exit(2);
        }
    }


    // =============================================================
    // PROCESSOR SELECTION
    // =============================================================

    private static CDRProcessor createProcessor(
            FileInfo fileInfo) {

        if (fileInfo == null ||
                fileInfo.getFormat() == null) {

            return null;
        }


        return switch (fileInfo.getFormat()) {

            case DOC ->
                    new DOCCDRProcessor();

            case DOCX ->
                    new DOCXCDRProcessor();

            case PPT ->
                    new PPTCDRProcessor();

            case PPTX ->
                    new PPTXCDRProcessor();

            case XLS ->
                    new XLSCDRProcessor();

            case XLSX ->
                    new XLSXCDRProcessor();

            case PDF ->
                    new PDFCDRProcessor();

            case RTF ->
                    new RTFCDRProcessor();

            default ->
                    null;
        };
    }


    // =============================================================
    // UNIVERSAL SUMMARY
    // =============================================================

    private static void printSummary(
            Path inputFile,
            Path outputFile,
            CDRResult result) {

        System.out.println();

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "              DOCSHIELD CDR"
        );

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "Input  : " +
                inputFile
        );

        System.out.println(
                "Output : " +
                outputFile
        );
        System.out.println("Input SHA-256  : " + result.getInputSha256());
        System.out.println("Output SHA-256 : " + result.getOutputSha256());
        System.out.println("Original Copy  : " + result.isOriginalCopied());
        System.out.println(
                "Reconstructed  : " +
                (result.isOriginalCopied()
                        ? "NO (clean input - original copied unchanged)"
                        : result.isReconstructionSuccessful()
                                ? "YES"
                                : "NO (FAILED)")
        );

        System.out.println();


        if (result.hasThreats()) {
            System.out.println("Threat : YES");
            System.out.println("Initial findings : " + result.getFindings().size());
            System.out.println("Type   : " + result.getThreatSummary());
            System.out.println("Level  : " + result.getHighestSeverity());
            System.out.println("Action : " + (result.isThreatRemoved() ? "REMOVED" : "NOT REMOVED"));
        } else if (result.hasBlockingFindings()) {
            System.out.println("Threat : NO");
            System.out.println("Policy/Security findings : YES (" + result.getFindings().size() + ")");
            System.out.println("Action : " + (result.isThreatRemoved() ? "RESOLVED" : "NOT RESOLVED"));
        } else {
            System.out.println("Threat : NO");
            System.out.println("Initial findings : " + result.getFindings().size());
        }

        System.out.println("Final findings   : " + result.getFinalFindings().size() +
                (result.getFinalFindings().isEmpty() ? " (CLEAN)" : " (REMAINING)"));


        System.out.println();

        System.out.println(
                "Integrity      : " +
                (
                        result.isIntegrityPassed()
                                ? "PASS"
                                : "FAIL"
                )
        );

        System.out.println();


        System.out.println(
                "Report : output/reports/" +
                inputFile.getFileName() +
                "_CDR_Report.txt"
        );

        System.out.println(
                "=============================================="
        );
    }
}
