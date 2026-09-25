package reconstruction;

import model.ooxml.OOXMLPackage;
import org.apache.poi.xslf.usermodel.XMLSlideShow;
import org.junit.jupiter.api.Test;
import parsing.ooxml.OOXMLPackageReader;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class OOXMLPPTXRoundTripTest {
    @Test
    void pptxUsesTheCommonOoxmlPackageReaderAndWriter() throws Exception {
        Path input = Files.createTempFile("docshield-pptx-fixture-", ".pptx");

        try (XMLSlideShow presentation = new XMLSlideShow();
             OutputStream output = Files.newOutputStream(input)) {
            var slide = presentation.createSlide();
            slide.createTextBox().setText("DocShield controlled PPTX test fixture");
            presentation.write(output);
        }

        try {
            assertTrue(Files.exists(input), "Generated PPTX fixture is missing: " + input);

            OOXMLPackageReader reader = new OOXMLPackageReader();
            OOXMLPackage original = reader.read(input);
            Path output = Files.createTempFile("docshield-pptx-", ".pptx");
            try {
                new OOXMLPackageWriter().write(original, output);
                OOXMLPackage roundTrip = reader.read(output);
                assertEquals(original.getPartCount(), roundTrip.getPartCount());
                assertEquals(original.getRelationshipCount(), roundTrip.getRelationshipCount());
                assertEquals(original.getContentTypes().size(), roundTrip.getContentTypes().size());
            } finally {
                Files.deleteIfExists(output);
            }
        } finally {
            Files.deleteIfExists(input);
        }
    }
}
