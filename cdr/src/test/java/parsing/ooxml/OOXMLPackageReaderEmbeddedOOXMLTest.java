package parsing.ooxml;

import model.ooxml.OOXMLPackage;
import model.ooxml.OOXMLPart;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/** Regression test for embedded OOXML package MIME types. */
class OOXMLPackageReaderEmbeddedOOXMLTest {
    @Test
    void embeddedXlsxPackageIsNotMisclassifiedAsXml() throws Exception {
        byte[] embedded = minimalXlsx();
        byte[] outer = minimalOuterPptxWithEmbeddedXlsx(embedded);
        Path temp = Files.createTempFile("docshield-embedded-xlsx-", ".pptx");
        try {
            Files.write(temp, outer);
            OOXMLPackage pkg = new OOXMLPackageReader().read(temp);
            OOXMLPart part = pkg.getPart("ppt/embeddings/Microsoft_Excel_Worksheet.xlsx");
            assertNotNull(part);
            assertEquals("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", part.getContentType());
            assertFalse(part.isXml(), "An embedded .xlsx ZIP package must not be parsed as XML");
        } finally { Files.deleteIfExists(temp); }
    }
    private static byte[] minimalOuterPptxWithEmbeddedXlsx(byte[] embedded) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            put(zip, "[Content_Types].xml", "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/ppt/presentation.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml\"/><Override PartName=\"/ppt/embeddings/Microsoft_Excel_Worksheet.xlsx\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\"/></Types>");
            put(zip, "_rels/.rels", "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>");
            put(zip, "ppt/presentation.xml", "<?xml version=\"1.0\"?><p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"/>");
            put(zip, "ppt/embeddings/Microsoft_Excel_Worksheet.xlsx", embedded);
        }
        return out.toByteArray();
    }
    private static byte[] minimalXlsx() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            put(zip, "[Content_Types].xml", "<?xml version=\"1.0\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/></Types>");
            put(zip, "_rels/.rels", "<?xml version=\"1.0\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"/>");
            put(zip, "xl/workbook.xml", "<?xml version=\"1.0\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"/>");
        }
        return out.toByteArray();
    }
    private static void put(ZipOutputStream zip, String name, String data) throws IOException { put(zip, name, data.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
    private static void put(ZipOutputStream zip, String name, byte[] data) throws IOException { zip.putNextEntry(new ZipEntry(name)); zip.write(data); zip.closeEntry(); }
}
