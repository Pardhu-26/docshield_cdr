package parsing.ppt;

import model.common.DocumentModel;
import parsing.common.DocumentParser;
import parsing.pptx.PPTXParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Legacy PPT parser boundary.
 *
 * <p>Legacy binary PowerPoint documents are first converted by the isolated
 * LibreOffice subprocess boundary and then parsed as PPTX by DocShield's
 * OOXML parser. No native in-process HSLF parsing is used.</p>
 */
public class PPTParser implements DocumentParser {

    private PPTParseResult parseResult;

    @Override
    public DocumentModel parse(Path file) throws IOException {
        parseResult = new PPTParseResult();
        parseResult.setParserUsed("LibreOffice -> PPTXParser");

        PPTToPPTXConverter converter = new PPTToPPTXConverter();
        Path convertedFile = converter.convert(file);

        try {
            DocumentModel model = new PPTXParser().parse(convertedFile);

            parseResult.setParseSucceeded(true);
            parseResult.setExtractionValid(true);
            parseResult.setTextCount(model.getTextComponents().size());
            parseResult.setImageCount(model.getImageComponents().size());
            parseResult.setEmbeddedObjectCount(model.getEmbeddedObjectComponents().size());
            parseResult.setSlideCount(model.getStructureComponents().size());

            return model;
        } catch (Exception e) {
            parseResult.setParseSucceeded(false);
            parseResult.setExtractionValid(false);
            parseResult.setFailureReason("PPTX parsing after LibreOffice conversion failed: " + e.getMessage());
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("PPTX parsing after LibreOffice conversion failed.", e);
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

    public PPTParseResult getParseResult() {
        return parseResult;
    }
}
