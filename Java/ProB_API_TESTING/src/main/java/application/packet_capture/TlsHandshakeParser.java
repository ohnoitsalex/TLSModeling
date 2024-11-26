
package application.packet_capture;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class TlsHandshakeParser {

    // Parse TLS handshake record
    public static void parseTlsHandshakeRecord(byte[] rawData) {

        if (rawData.length < 6 || rawData[0] != (byte) 0x16) { // 0x16 = TLS Handshake
            System.out.println("Not a TLS Handshake Record.");
            return;
        }

        int handshakeType = rawData[5] & 0xFF; // Byte 5: Handshake Type
        System.out.println("Handshake Type: " + getHandshakeType(handshakeType));

        int length = ((rawData[6] & 0xFF) << 16) | ((rawData[7] & 0xFF) << 8) | (rawData[8] & 0xFF);
        System.out.println("Handshake Length: " + length);

        ByteBuffer buffer = ByteBuffer.wrap(rawData, 9, length); // Start parsing from byte 9

        switch (handshakeType) {
            case 0x01: // ClientHello
                parseClientHello(buffer);
                break;
            case 0x02: // ServerHello
                parseServerHello(buffer);
                break;
            default:
                System.out.println("Unsupported Handshake Type.");
        }
    }

    // Parse ClientHello
    private static void parseClientHello(ByteBuffer buffer) {
        System.out.println("=== ClientHello ===");

        // Protocol Version (2 bytes)
        int versionMajor = buffer.get() & 0xFF;
        int versionMinor = buffer.get() & 0xFF;
        System.out.printf("Version: SSL %d.%d%n", versionMajor, versionMinor);

        // Random (32 bytes)
        byte[] random = new byte[32];
        buffer.get(random);
        System.out.println("Random: " + bytesToHex(random));

        // Session ID Length (1 byte) + Session ID
        int sessionIdLength = buffer.get() & 0xFF;
        byte[] sessionId = new byte[sessionIdLength];
        buffer.get(sessionId);
        System.out.println("Session ID: " + bytesToHex(sessionId));

        // Cipher Suites Length (2 bytes) + Cipher Suites
        int cipherSuitesLength = buffer.getShort() & 0xFFFF;
        System.out.println("Cipher Suites Length: " + cipherSuitesLength);
        List<String> cipherSuites = new ArrayList<>();
        for (int i = 0; i < cipherSuitesLength; i += 2) {
            cipherSuites.add(String.format("0x%04x", buffer.getShort()));
        }
        System.out.println("Cipher Suites: " + cipherSuites);

        // Compression Methods Length (1 byte) + Compression Methods
        int compressionMethodsLength = buffer.get() & 0xFF;
        System.out.println("Compression Methods Length: " + compressionMethodsLength);
        byte[] compressionMethods = new byte[compressionMethodsLength];
        buffer.get(compressionMethods);
        System.out.println("Compression Methods: " + bytesToHex(compressionMethods));

        // Extensions Length (2 bytes) + Extensions
        if (buffer.remaining() > 2) {
            int extensionsLength = buffer.getShort() & 0xFFFF;
            System.out.println("Extensions Length: " + extensionsLength);
            parseExtensions(true, buffer, extensionsLength);
        }
    }

    // Parse ServerHello
    private static void parseServerHello(ByteBuffer buffer) {
        System.out.println("=== ServerHello ===");

        // Protocol Version (2 bytes)
        int versionMajor = buffer.get() & 0xFF;
        int versionMinor = buffer.get() & 0xFF;
        System.out.printf("Version: SSL %d.%d%n", versionMajor, versionMinor);

        // Random (32 bytes)
        byte[] random = new byte[32];
        buffer.get(random);
        System.out.println("Random: " + bytesToHex(random));

        // Session ID Length (1 byte) + Session ID
        int sessionIdLength = buffer.get() & 0xFF;
        byte[] sessionId = new byte[sessionIdLength];
        buffer.get(sessionId);
        System.out.println("Session ID Length: " + sessionIdLength);
        System.out.println("Session ID: " + bytesToHex(sessionId));

        // Cipher Suite (2 bytes)
        int cipherSuite = buffer.getShort() & 0xFFFF;
        System.out.printf("Cipher Suite: 0x%04x%n", cipherSuite);

        // Compression Method (1 byte)
        int compressionMethod = buffer.get() & 0xFF;
        System.out.printf("Compression Method: 0x%02x%n", compressionMethod);

        // Extensions Length (2 bytes) + Extensions
        if (buffer.remaining() > 2) {
            int extensionsLength = buffer.getShort() & 0xFFFF;
            System.out.println("Extensions Length: " + extensionsLength);
            parseExtensions(false, buffer, extensionsLength);
        }
    }

    // Parse TLS Extensions
    private static void parseExtensions(Boolean isClient, ByteBuffer buffer, int extensionsLength) {
        System.out.println("=== Extensions ===");
        int bytesRead = 0;
        while (bytesRead < extensionsLength) {
            int extensionType = buffer.getShort() & 0xFFFF;
            int extensionLength = buffer.getShort() & 0xFFFF;

            byte[] extensionData = new byte[extensionLength];
            buffer.get(extensionData);

            String type = "unknown";
            String data = "\tData: "+ bytesToHex(extensionData);
            switch (extensionType) {
                case 0x002b: // supported_versions
                    type = "supported_versions";
                    data = parseSupportedVersionsExtension(extensionLength, extensionData);
                    break;
                case 0x0033: // key_share
                    type = "key_share";
                    //data = parseKeyShareExtension(isClient, extensionData);
                    break;
                default:
                    type = String.format("unknown (0x%04x)", extensionType);
            }
            System.out.printf("* Extension: %s (len=%d) \n", type, extensionLength);
            System.out.printf("\tType: %s (%d)\n\tLength: %d\n%s\n", type, extensionType, extensionLength, data);

            bytesRead += 4 + extensionLength; // 4 bytes for type + length, plus data
        }
    }

    private static String parseSupportedVersionsExtension(int dataLength, byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i = 0;
        if (dataLength%2 != 0) {
            sb.append(String.format("\tSupportedVersion length: %d \n", dataLength - 1));
            i++;
        }
        while (i < dataLength) {
            int versionMajor = data[i] & 0xFF;
            int versionMinor = data[i + 1] & 0xFF;
            sb.append(String.format("\tVersion: SSL %d.%d%n", versionMajor, versionMinor));
            i = i+ 2;
        }
        return sb.toString();
    }

    private static String parseKeyShareExtension(boolean isClient, byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("\tKey Share Extension\n");
        int i=0;
        if (isClient) {
            sb.append("\tClient Key Share Length:"+ data[i]);
            i++;
        }
        while (i < data.length) {
            // Group 2 Bytes
            int first = data[i] & 0xff;
            int second = data[i + 1] & 0xff;
            int group = ((first & 0xff) << 8) | (second & 0xff);
            System.out.printf("Group: 0x%04x\n", group);
            i += 2;

            // Key exchange length
            byte[] keyData = Arrays.copyOfRange(data, i, data.length);
            int keyLength = keyData.length;
            System.out.printf("Key Exchange Length: %d\n", keyLength);
            System.out.printf("\tKey: %s\n", bytesToHex(keyData));

            //sb.append("\tKey Share Entry:");
        }

        return sb.toString();
    }

    // Helper to identify handshake type
    private static String getHandshakeType(int type) {
        switch (type) {
            case 0x01:
                return "ClientHello";
            case 0x02:
                return "ServerHello";
            default:
                return "Unknown (0x" + String.format("%02x", type) + ")";
        }
    }

    // Helper to convert TLS version code to the decimal version
    private static String getTLSVersionFromHexadecimal(int tlsVersion) {
        int hex = tlsVersion & 0xFFFF;
        return switch (tlsVersion) {
            case 0x0304 -> "TLS 1.3";
            case 0x0303 -> "TLS 1.2";
            case 0x0302 -> "TLS 1.1";
            case 0x0301 -> "TLS 1.0";
            case 0x0300 -> "SSL 3.0";
            default -> "Unknown (0x" + String.format("%04x", tlsVersion) + ")";
        };
    }

    // Helper to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x ", b));
        }
        return hex.toString().trim();
    }

}