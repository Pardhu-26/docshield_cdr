package identification;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileIdentifierRTFTest {

    @Test
    void identifiesStandardRtf() throws Exception {
        Path file = Files.createTempFile("docshield-rtf-", ".rtf");
        try {
            Files.writeString(file, "{\\rtf1\\ansi Test}", StandardCharsets.ISO_8859_1);
            FileInfo info = new FileIdentifier().identify(file);
            assertEquals(Format.RTF, info.getFormat());
            assertTrue(info.isExtensionMatch());
        } finally {
            Files.deleteIfExists(file);
        }
    }

    @Test
    void identifiesRtfWithUtf8BomAndLeadingWhitespace() throws Exception {
        Path file = Files.createTempFile("docshield-rtf-", ".rtf");
        try {
            byte[] body = "{\\rtf1\\ansi Test}".getBytes(StandardCharsets.ISO_8859_1);
            byte[] prefix = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, ' ', '\n'};
            byte[] all = new byte[prefix.length + body.length];
            System.arraycopy(prefix, 0, all, 0, prefix.length);
            System.arraycopy(body, 0, all, prefix.length, body.length);
            Files.write(file, all);

            FileInfo info = new FileIdentifier().identify(file);
            assertEquals(Format.RTF, info.getFormat());
            assertTrue(info.isExtensionMatch());
        } finally {
            Files.deleteIfExists(file);
        }
    }
}
