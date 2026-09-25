package model.ooxml;

import java.util.Arrays;

public class OOXMLPart {

    private String partName;

    private String contentType;

    private byte[] data;

    private boolean xml;


    public OOXMLPart() {
    }


    public OOXMLPart(
            String partName,
            String contentType,
            byte[] data) {

        this.partName = partName;
        this.contentType = contentType;
        this.data = data;

        this.xml =
                isXmlContentType(
                        contentType
                );
    }


    public String getPartName() {
        return partName;
    }


    public String getContentType() {
        return contentType;
    }


    public byte[] getData() {
        return data;
    }


    public boolean isXml() {
        return xml;
    }


    public void setPartName(
            String partName) {

        this.partName = partName;
    }


    public void setContentType(
            String contentType) {

        this.contentType =
                contentType;

        this.xml =
                isXmlContentType(
                        contentType
                );
    }


    public void setData(
            byte[] data) {

        this.data = data;
    }


    public void setXml(
            boolean xml) {

        this.xml = xml;
    }


    public byte[] copyData() {

        if (data == null) {
            return null;
        }

        return Arrays.copyOf(
                data,
                data.length
        );
    }


    private boolean isXmlContentType(
            String contentType) {

        if (contentType == null) {
            return false;
        }

        String normalized = contentType
                .trim()
                .toLowerCase(java.util.Locale.ROOT);

        // Do not use contains("xml") here. OOXML package MIME types such as
        // application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
        // contain the word "xml" but the part itself is a ZIP package, not
        // an XML document. Treat only actual XML media types as XML parts.
        return normalized.equals("application/xml")
                || normalized.equals("text/xml")
                || normalized.endsWith("+xml")
                || normalized.endsWith("/xml");
    }


    @Override
    public String toString() {

        return "OOXMLPart{" +
                "partName='" +
                partName +
                '\'' +
                ", contentType='" +
                contentType +
                '\'' +
                ", dataSize=" +
                (data == null
                        ? 0
                        : data.length) +
                ", xml=" +
                xml +
                '}';
    }
}