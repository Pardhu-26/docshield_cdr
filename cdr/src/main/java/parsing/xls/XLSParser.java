package parsing.xls;

import model.common.DocumentModel;
import parsing.common.DocumentParser;
import parsing.xlsx.XLSXParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Legacy XLS parser boundary.
 *
 * <p>Legacy binary Excel workbooks are first converted by the isolated
 * LibreOffice subprocess boundary and then parsed as XLSX by DocShield's
 * OOXML parser. No native in-process HSSF parsing is used.</p>
 */
public class XLSParser implements DocumentParser {

    private XLSParseResult parseResult;

    @Override
    public DocumentModel parse(Path file) throws IOException {
        parseResult = new XLSParseResult();
        parseResult.setParserUsed("LibreOffice -> XLSXParser");

        XLSToXLSXConverter converter = new XLSToXLSXConverter();
        Path convertedFile = converter.convert(file);

        try {
            DocumentModel model = new XLSXParser().parse(convertedFile);

            parseResult.setParseSucceeded(true);
            parseResult.setExtractionValid(true);
            parseResult.setTextCount(model.getTextComponents().size());
            parseResult.setImageCount(model.getImageComponents().size());
            parseResult.setEmbeddedObjectCount(model.getEmbeddedObjectComponents().size());
            parseResult.setSheetCount(model.getStructureComponents().size());
            parseResult.setCellCount(model.getTextComponents().size());

            return model;
        } catch (Exception e) {
            parseResult.setParseSucceeded(false);
            parseResult.setExtractionValid(false);
            parseResult.setFailureReason("XLSX parsing after LibreOffice conversion failed: " + e.getMessage());
            if (e instanceof IOException io) {
                throw io;
            }
            throw new IOException("XLSX parsing after LibreOffice conversion failed.", e);
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

    public XLSParseResult getParseResult() {
        return parseResult;
    }
}
