package identification;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileIdentifier {

    public FileInfo identify(Path file) throws IOException {

        if (!Files.exists(file)) {
            throw new IOException("File does not exist: " + file);
        }

        if (!Files.isRegularFile(file)) {
            throw new IOException(
                    "Path is not a regular file: " + file
            );
        }

        String fileName =
                file.getFileName().toString();

        long fileSize =
                Files.size(file);

        String sha256 =
                calculateSha256(file);

        String extension =
                getExtension(fileName);

        String mimeType =
                Files.probeContentType(file);

        // Detect actual format
        Format format =
                detectFormat(file);

        // Check whether extension agrees
        boolean extensionMatch =
                isExtensionMatch(
                        extension,
                        format
                );

        // File is valid when:
        // 1. We successfully identified the format
        // 2. Extension matches detected format
        boolean valid =
                format != Format.UNKNOWN
                        && extensionMatch;

        FileInfo info =
                new FileInfo(
                        fileName,
                        fileSize,
                        extension,
                        mimeType,
                        sha256,
                        format,
                        valid,
                        extensionMatch
                );

        return info;
    }

    private boolean isExtensionMatch(
            String extension,
            Format format) {

        switch (format) {

            case PDF:
                return extension.equals("pdf");

            case DOC:
                return extension.equals("doc");

            case DOCX:
                return extension.equals("docx");

            case PPT:
                return extension.equals("ppt");

            case PPTX:
                return extension.equals("pptx");

            case XLS:
                return extension.equals("xls");

            case XLSX:
                return extension.equals("xlsx");

            case RTF:
                return extension.equals("rtf");

            default:
                return false;
        }
    }

    private boolean hasZipSignature(Path file) throws IOException {
        try (InputStream inputStream = Files.newInputStream(file)) {
            int firstByte = inputStream.read();
            int secondByte = inputStream.read();
            int thirdByte = inputStream.read();
            int fourthByte = inputStream.read();
            return firstByte == 0x50 && secondByte == 0x4B && thirdByte == 0x03 && fourthByte == 0x04;
        }
    }

    private boolean hasDocxStructure(Path file) {
        try (ZipFile zipFile = new ZipFile(file.toFile())) {
            boolean contentTypes = false;
            boolean documentXml = false;
            var entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.equals("[Content_Types].xml")) {
                    contentTypes = true;
                }
                if (name.equals("word/document.xml")) {
                    documentXml = true;
                }
            }
            return contentTypes && documentXml;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean hasWordprocessingContentType(Path file) {
        try (ZipFile zipFile = new ZipFile(file.toFile())) {
            ZipEntry entry = zipFile.getEntry("[Content_Types].xml");
            if (entry == null) {
                return false;
            }
            try (InputStream inputStream = zipFile.getInputStream(entry)) {
                String content = new String(
                        inputStream.readAllBytes()
                );
                return content.contains(
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
                );
            }
        } catch (IOException e) {
            return false;
        }
    }

    private String calculateSha256(Path file) throws IOException {
        try {
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream inputStream = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }
            }
            byte[] hash = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    private String getExtension(String fileName) {
        int lastDot = fileName.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        return fileName.substring(lastDot + 1).toLowerCase();
    }

    private boolean isPdf(byte[] header) {
        return header.length >= 5 && header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F' && header[4] == '-';
    }

    private boolean isRtf(byte[] header) {
        if (header == null || header.length < 5) {
            return false;
        }
        int offset = 0;
        // Allow an optional UTF-8 BOM before the RTF header.
        if (header.length >= 3
                && (header[0] & 0xFF) == 0xEF
                && (header[1] & 0xFF) == 0xBB
                && (header[2] & 0xFF) == 0xBF) {
            offset = 3;
        }
        while (offset < header.length
                && (header[offset] == ' ' || header[offset] == '\t'
                || header[offset] == '\r' || header[offset] == '\n')) {
            offset++;
        }
        return header.length - offset >= 5
                && header[offset] == '{'
                && header[offset + 1] == '\\'
                && header[offset + 2] == 'r'
                && header[offset + 3] == 't'
                && header[offset + 4] == 'f';
    }

    private boolean isOle(byte[] header) {
        return header.length >= 8 && (header[0] & 0xFF) == 0xD0 && (header[1] & 0xFF) == 0xCF && (header[2] & 0xFF) == 0x11 && (header[3] & 0xFF) == 0xE0 && (header[4] & 0xFF) == 0xA1 && (header[5] & 0xFF) == 0xB1 && (header[6] & 0xFF) == 0x1A && (header[7] & 0xFF) == 0xE1;
    }

    private Format detectOOXML(Path file) throws IOException {
        try (ZipFile zipFile = new ZipFile(file.toFile())) {
            boolean hasContentTypes = zipFile.getEntry("[Content_Types].xml") != null;
            if (!hasContentTypes) {
                return Format.UNKNOWN;
            }
            boolean hasWord = zipFile.getEntry("word/document.xml") != null;
            boolean hasPresentation = zipFile.getEntry("ppt/presentation.xml") != null;
            boolean hasWorkbook = zipFile.getEntry("xl/workbook.xml") != null;
            if (hasWord) {
                return Format.DOCX;
            }
            if (hasPresentation) {
                return Format.PPTX;
            }
            if (hasWorkbook) {
                return Format.XLSX;
            }
            return Format.UNKNOWN;
        }
    }

    private Format detectFormat(Path file) throws IOException {
        byte[] header = Files.readAllBytes(file);
        if (isPdf(header)) {
            return Format.PDF;
        }
        if (isRtf(header)) {
            return Format.RTF;
        }
        if (isOle(header)) {
            String extension = getExtension(file.getFileName().toString());
            switch (extension) {
                case "doc":
                    return Format.DOC;
                case "ppt":
                    return Format.PPT;
                case "xls":
                    return Format.XLS;
                default:
                    return Format.UNKNOWN;
            }
        }
        if (isZip(header)) {
            return detectOOXML(file);
        }
        return Format.UNKNOWN;
    }

    private boolean isZip(byte[] header) {
        return header.length >= 4 && header[0] == 'P' && header[1] == 'K' && header[2] == 3 && header[3] == 4;
    }
}