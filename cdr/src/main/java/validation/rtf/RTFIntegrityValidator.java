package validation.rtf;

import model.common.DocumentModel;
import parsing.rtf.RTFParser;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Structural integrity validator for reconstructed Rich Text Format documents.
 * Verifies magic signature, strict group brace depth balancing, and readability
 * by the semantic RTF parser without exceptions.
 */
public final class RTFIntegrityValidator {

    public boolean validate(Path file) {
        if (file == null || !Files.exists(file) || !Files.isRegularFile(file)) {
            return false;
        }

        try {
            long size = Files.size(file);
            if (size <= 0) {
                return false;
            }

            // 1. Verify RTF magic signature
            byte[] header = new byte[Math.min((int) size, 4096)];
            try (InputStream in = Files.newInputStream(file)) {
                int read = in.read(header);
                if (read < 5) {
                    return false;
                }
            }

            int offset = 0;
            if (header.length >= 3 && (header[0] & 0xFF) == 0xEF && (header[1] & 0xFF) == 0xBB && (header[2] & 0xFF) == 0xBF) {
                offset = 3;
            }
            while (offset < header.length && (header[offset] == ' ' || header[offset] == '\t' || header[offset] == '\r' || header[offset] == '\n')) {
                offset++;
            }
            if (header.length - offset < 5
                    || header[offset] != '{'
                    || header[offset + 1] != '\\'
                    || header[offset + 2] != 'r'
                    || header[offset + 3] != 't'
                    || header[offset + 4] != 'f') {
                return false;
            }

            // 2. Verify strict brace depth balance across the whole file
            try (InputStream in = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                int depth = 0;
                boolean escaped = false;

                while ((bytesRead = in.read(buffer)) != -1) {
                    for (int i = 0; i < bytesRead; i++) {
                        char c = (char) (buffer[i] & 0xFF);
                        if (escaped) {
                            escaped = false;
                            continue;
                        }
                        if (c == '\\') {
                            escaped = true;
                            continue;
                        }
                        if (c == '{') {
                            depth++;
                        } else if (c == '}') {
                            depth--;
                            if (depth < 0) {
                                return false; // Underflow
                            }
                        }
                    }
                }
                if (depth != 0) {
                    return false; // Unclosed group
                }
            }

            // 3. Verify that the semantic parser can ingest the reconstructed document
            RTFParser parser = new RTFParser();
            DocumentModel model = parser.parse(file);
            if (model == null) {
                return false;
            }

            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}
