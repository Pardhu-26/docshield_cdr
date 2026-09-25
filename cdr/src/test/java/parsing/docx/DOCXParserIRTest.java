package parsing.docx;

import model.common.DocumentModel;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DOCXParserIRTest {

    @TempDir
    Path tempDir;

    @Test
    void parsesTextAndImagesIntoCommonIr() throws Exception {
        Path input = tempDir.resolve("sample.docx");

        // Keep this regression test self-contained so CI does not depend on
        // a developer's personal document or an untracked samples directory.
        try (XWPFDocument document = new XWPFDocument();
             OutputStream output = Files.newOutputStream(input)) {
            document.createParagraph().createRun()
                    .setText("DocShield controlled DOCX test fixture");
            document.write(output);
        }

        assertTrue(Files.exists(input), "DOCX fixture is missing: " + input);

        DocumentModel model = new DOCXParser().parse(input);

        assertFalse(model.getTextComponents().isEmpty(),
                "DOCX text was not populated into the common IR");
        assertTrue(model.getTextComponents().stream().anyMatch(c ->
                        c.getText() != null && !c.getText().isBlank()),
                "DOCX IR text is blank");

        for (var image : model.getImageComponents()) {
            assertNotNull(image.getFileName());
            assertNotNull(image.getData());
            assertTrue(image.getData().length > 0);
        }
    }
}
