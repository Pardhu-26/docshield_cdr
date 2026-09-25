package parsing.doc;

import model.common.DocumentModel;
import parsing.common.DocumentParser;
import parsing.docx.DOCXParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Legacy DOC parser boundary.
 *
 * <p>Legacy binary Office documents are never parsed with a native in-process
 * Office parser. They are first converted by the isolated LibreOffice
 * subprocess boundary and then parsed as DOCX by DocShield's OOXML parser.</p>
 */
public class DOCParser implements DocumentParser {

    private DOCParseResult parseResult;

    @Override
    public DocumentModel parse(Path file) throws IOException {
        parseResult = new DOCParseResult();
        parseResult.setParserUsed("LibreOffice -> DOCXParser");

        DOCToDOCXConverter converter = new DOCToDOCXConverter();
        Path convertedFile = converter.convert(file);

        try {
            DocumentModel model = new DOCXParser().parse(convertedFile);

            parseResult.setParseSucceeded(true);
            parseResult.setExtractionValid(true);
            parseResult.setTextCount(model.getTextComponents().size());
            parseResult.setImageCount(model.getImageComponents().size());
            parseResult.setEmbeddedObjectCount(model.getEmbeddedObjectComponents().size());
            parseResult.setParagraphCount(model.getTextComponents().size());

            return model;
        } catch (Exception e) {
            parseResult.setParseSucceeded(false);
            parseResult.setExtractionValid(false);
            parseResult.setFailureReason("DOCX parsing after LibreOffice conversion failed: " + e.getMessage());
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("DOCX parsing after LibreOffice conversion failed.", e);
        } finally {
            try {
                Files.deleteIfExists(convertedFile);
                Path temporaryDirectory = convertedFile.getParent();
                if (temporaryDirectory != null) {
                    Files.deleteIfExists(temporaryDirectory);
                }
            } catch (IOException ignored) {
                // Cleanup failure must not mask the parse result.
            }
        }
    }

    public DOCParseResult getParseResult() {
        return parseResult;
    }
}
