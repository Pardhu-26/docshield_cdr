package validation.rtf;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class RTFIntegrityValidatorTest {

    private final RTFIntegrityValidator validator = new RTFIntegrityValidator();

    @Test
    void validatesCleanSampleRtf() throws Exception {
        Path temp = Files.createTempFile("docshield-rtf-clean-", ".rtf");
        try {
            Files.writeString(temp, "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Courier;}}\\f0\\fs24 Clean DocShield fixture.\\par}");
            assertTrue(validator.validate(temp));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    @Test
    void validatesMinimalRtfFile() throws Exception {
        Path temp = Files.createTempFile("docshield-rtf-valid-", ".rtf");
        try {
            Files.writeString(temp, "{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Courier;}}\\f0\\fs24 Hello World!\\par}");
            assertTrue(validator.validate(temp));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    @Test
    void rejectsEmptyFile() throws Exception {
        Path temp = Files.createTempFile("docshield-rtf-empty-", ".rtf");
        try {
            assertFalse(validator.validate(temp));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    @Test
    void rejectsNonRtfFile() throws Exception {
        Path temp = Files.createTempFile("docshield-rtf-invalid-", ".rtf");
        try {
            Files.writeString(temp, "%PDF-1.7 not an rtf document");
            assertFalse(validator.validate(temp));
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    @Test
    void rejectsUnbalancedBraces() throws Exception {
        Path temp = Files.createTempFile("docshield-rtf-unbalanced-", ".rtf");
        try {
            Files.writeString(temp, "{\\rtf1\\ansi {\\b Unclosed group");
            assertFalse(validator.validate(temp));
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
