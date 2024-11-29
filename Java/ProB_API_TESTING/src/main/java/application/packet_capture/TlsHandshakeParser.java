
package application.packet_capture;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static application.packet_capture.PacketLogger.writeData;

public class TlsHandshakeParser {

    public static final String writerFilePath = "tls_handshake_data.txt";

    // Parse TLS handshake record
    public static void parseTlsHandshakeRecord(byte[] rawData) {

        if (rawData.length < 6 || rawData[0] != (byte) 0x16) { // 0x16 = TLS Handshake
            writeData("Not a TLS Handshake Record.", writerFilePath);
            System.out.println("Not a TLS Handshake Record.");
            return;
        }

        int handshakeType = rawData[5] & 0xFF; // Byte 5: Handshake Type
        writeData("Handshake Type: " + getHandshakeType(handshakeType), writerFilePath);
        System.out.println("Handshake Type: " + getHandshakeType(handshakeType));

        int length = ((rawData[6] & 0xFF) << 16) | ((rawData[7] & 0xFF) << 8) | (rawData[8] & 0xFF);
        writeData("Handshake Length: " + length, writerFilePath);
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
                writeData("Unsupported Handshake Type.", writerFilePath);
                System.out.println("Unsupported Handshake Type.");
        }
    }

    // Parse ClientHello
    private static void parseClientHello(ByteBuffer buffer) {
        writeData("=== ClientHello ===", writerFilePath);
        System.out.println("=== ClientHello ===");

        // Protocol Version (2 bytes)
        int versionMajor = buffer.get() & 0xFF;
        int versionMinor = buffer.get() & 0xFF;
        writeData(String.format("Version: 0%d0%d%n", versionMajor, versionMinor), writerFilePath);
        System.out.printf("Version: 0%d0%d%n", versionMajor, versionMinor);

        // Random (32 bytes)
        byte[] random = new byte[32];
        buffer.get(random);
        writeData("Random: " + bytesToHex(random), writerFilePath);
        System.out.println("Random: " + bytesToHex(random));

        // Session ID Length (1 byte) + Session ID
        int sessionIdLength = buffer.get() & 0xFF;
        byte[] sessionId = new byte[sessionIdLength];
        buffer.get(sessionId);
        writeData("Session ID: " + bytesToHex(sessionId), writerFilePath);
        System.out.println("Session ID: " + bytesToHex(sessionId));

        // Cipher Suites Length (2 bytes) + Cipher Suites
        int cipherSuitesLength = buffer.getShort() & 0xFFFF;
        writeData("Cipher Suites Length: " + cipherSuitesLength, writerFilePath);
        System.out.println("Cipher Suites Length: " + cipherSuitesLength);
        List<String> cipherSuites = new ArrayList<>();
        for (int i = 0; i < cipherSuitesLength; i += 2) {
            cipherSuites.add(String.format("0x%04x", buffer.getShort()));
        }
        writeData("Cipher Suites: " + cipherSuites, writerFilePath);
        System.out.println("Cipher Suites: " + cipherSuites);

        // Compression Methods Length (1 byte) + Compression Methods
        int compressionMethodsLength = buffer.get() & 0xFF;
        writeData("Compression Methods Length: " + compressionMethodsLength, writerFilePath);
        System.out.println("Compression Methods Length: " + compressionMethodsLength);
        byte[] compressionMethods = new byte[compressionMethodsLength];
        buffer.get(compressionMethods);
        writeData("Compression Methods: " + bytesToHex(compressionMethods), writerFilePath);
        System.out.println("Compression Methods: " + bytesToHex(compressionMethods));

        // Extensions Length (2 bytes) + Extensions
        if (buffer.remaining() > 2) {
            int extensionsLength = buffer.getShort() & 0xFFFF;
            writeData("Extensions Length: " + extensionsLength, writerFilePath);
            System.out.println("Extensions Length: " + extensionsLength);
            parseExtensions(true, buffer, extensionsLength);
        }
    }

    // Parse ServerHello
    private static void parseServerHello(ByteBuffer buffer) {
        writeData("=== ServerHello ===", writerFilePath);
        System.out.println("=== ServerHello ===");

        // Protocol Version (2 bytes)
        int versionMajor = buffer.get() & 0xFF;
        int versionMinor = buffer.get() & 0xFF;
        writeData(String.format("Version: 0%d0%d%n", versionMajor, versionMinor), writerFilePath);
        System.out.printf("Version: 0%d0%d%n", versionMajor, versionMinor);

        // Random (32 bytes)
        byte[] random = new byte[32];
        buffer.get(random);
        writeData("Random: " + bytesToHex(random), writerFilePath);
        System.out.println("Random: " + bytesToHex(random));

        // Session ID Length (1 byte) + Session ID
        int sessionIdLength = buffer.get() & 0xFF;
        byte[] sessionId = new byte[sessionIdLength];
        buffer.get(sessionId);
        writeData("Session ID Length: " + sessionIdLength, writerFilePath);
        writeData("Session ID: " + bytesToHex(sessionId), writerFilePath);
        System.out.println("Session ID Length: " + sessionIdLength);
        System.out.println("Session ID: " + bytesToHex(sessionId));

        // Cipher Suite (2 bytes)
        int cipherSuite = buffer.getShort() & 0xFFFF;
        writeData(String.format("Cipher Suite: 0x%04x%n", cipherSuite), writerFilePath);
        System.out.printf("Cipher Suite: 0x%04x%n", cipherSuite);

        // Compression Method (1 byte)
        int compressionMethod = buffer.get() & 0xFF;
        writeData(String.format("Compression Method: 0x%02x%n", compressionMethod), writerFilePath);
        System.out.printf("Compression Method: 0x%02x%n", compressionMethod);

        // Extensions Length (2 bytes) + Extensions
        if (buffer.remaining() > 2) {
            int extensionsLength = buffer.getShort() & 0xFFFF;
            writeData("Extensions Length: " + extensionsLength, writerFilePath);
            System.out.println("Extensions Length: " + extensionsLength);
            parseExtensions(false, buffer, extensionsLength);
        }
    }

    // Parse TLS Extensions
    private static void parseExtensions(Boolean isClient, ByteBuffer buffer, int extensionsLength) {
        writeData("=== Extensions ===", writerFilePath);
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
                case 0x0000: // server_name
                    type = "server_name";
                    data = parseServerNameExtension(extensionData);
                    break;
                case 0x002b: // supported_versions
                    type = "supported_versions";
                    data = parseSupportedVersionsExtension(extensionLength, extensionData);
                    break;
                case 0x0033: // key_share
                    type = "key_share";
                    data = parseKeyShareExtension(isClient, extensionData);
                    break;
                case 0x0005: // status_request
                    type = "status_request";
                    data = parseStatusRequestExtension(1, extensionData);
                    break;
                case 0x0011: // status_request
                    type = "status_request_v2";
                    data = parseStatusRequestExtension(2, extensionData);
                    break;
                case 0x000a: // supported_groups
                    type = "supported_groups";
                    data = parseSupportedGroupsExtension(extensionData);
                    break;
                case 0x000d: // signature_algorithms
                    type = "signature_algorithms";
                    data = parseSignatureAlgorithmsExtension(extensionData);
                    break;
                case 0x0032: // signature_algorithms
                    type = "signature_algorithms_cert";
                    data = parseSignatureAlgorithmsExtension(extensionData);
                    break;
                case 0x002d: // psk_key_exchange_modes
                    type = "psk_key_exchange_modes";
                    data = parsePskKeyExchangeModesExtension(extensionData);
                    break;
                default:
                    type = String.format("unknown (0x%04x)", extensionType);
            }
            writeData(String.format("* Extension: %s (len=%d) \n", type, extensionLength), writerFilePath);
            writeData(String.format("\tType: %s (%d)\n\tLength: %d\n%s\n", type, extensionType, extensionLength, data), writerFilePath);
            System.out.printf("* Extension: %s (len=%d) \n", type, extensionLength);
            System.out.printf("\tType: %s (%d)\n\tLength: %d\n%s\n", type, extensionType, extensionLength, data);

            bytesRead += 4 + extensionLength; // 4 bytes for type + length, plus data
        }
    }

    private static String parseServerNameExtension(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i= 0;
        while (i < data.length) {
            int entryLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
            sb.append(String.format("\tServer Name Entry length: %d\n", entryLength));

            int typeId = data[i+2];
            String typeName = (typeId == 0) ? ("DNS hostname" ) : ("unknown");
            sb.append(String.format("\t\tEntry type: %s\n", typeName));

            int lengthName = ((data[i+3] & 0xff) << 8) | (data[i+4] & 0xff);
            sb.append(String.format("\t\tEntry name length: %d\n", lengthName));
            i+=5;

            byte[] name = Arrays.copyOfRange(data, i, i+lengthName);
            sb.append(String.format("\t\tEntry name: %s\n", new String(name, StandardCharsets.UTF_8)));

            i+=lengthName;

        }
        return sb.toString();
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
            sb.append(String.format("\tVersion: 0%d0%d%n", versionMajor, versionMinor));
            i = i+ 2;
        }
        return sb.toString();
    }

    private static String parseKeyShareExtension(boolean isClient, byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("\tKey Share Extension\n");
        int i=0;
        if (isClient) {
            int keyShareLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
            sb.append(String.format("\tClient Key Share Length: %d\n", keyShareLength));
            i+= 2;
        }
        while (i < data.length) {
            // Group 2 Bytes
            int first = data[i] & 0xff;
            int second = data[i + 1] & 0xff;
            int group = ((first & 0xff) << 8) | (second & 0xff);
            sb.append(String.format("\t* Group: 0x%04x\n", group));
            i += 2;

            // Key exchange length
            int keyLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
            i += 2;

            // Key data
            byte[] keyData = Arrays.copyOfRange(data, i, i+keyLength);
            sb.append(String.format("\t\tKey Exchange Length: %d\n", keyLength));
            sb.append(String.format("\t\tKey: %s\n", bytesToHex(keyData)));
            i += keyLength;
        }
        return sb.toString();
    }

    // Helper to get
    private static String getCertificateStatusType(int codeType) {
        return switch (codeType) {
            case 0x01 -> "OCSP (1)";
            case 0x02 -> "OCSP Multi (2)";
            default -> "unknown (" + codeType + ")";
        };
    }

    private static String parseSupportedGroupsExtension(byte[] data) {
        StringBuilder sb = new StringBuilder();

        int listLength = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        sb.append(String.format("\tSupported Groups List Length: %d\n", listLength));

        sb.append("\tSupported Groups:\n");
        int i = 2;
        while (i < data.length) {
            int groupId = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
            sb.append(String.format("\t\t* Supported Group: %s\n", getGroupValue(groupId)));
            i += 2;
        }
        return sb.toString();
    }

    private static String parseStatusRequestExtension(int version, byte[] data) {
        StringBuilder sb = new StringBuilder();
        int i=0;
        if (version == 2) {
            // Certificate Status Length
            int statusLength = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
            sb.append(String.format("\tCertificate Status List Length: %d\n", statusLength));
            i+=2;
        }

        // Certificate Status Type
        String statusType = getCertificateStatusType(data[i]);
        sb.append(String.format("\tCertificate Status Type: %s\n", statusType));
        i++;

        if (version == 2) {
            // Certificate Status Length
            int statusLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
            sb.append(String.format("\tCertificate Status Length: %d\n", statusLength));
            i+=2;
        }

        // Responder ID list Length
        int listLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
        sb.append(String.format("\tResponder ID list Length: %d\n", listLength));
        i+=2;

        // Request Extensions Length
        int extensionsLength = ((data[i] & 0xff) << 8) | (data[i+1] & 0xff);
        sb.append(String.format("\tRequest Extensions Length: %d\n", extensionsLength));

        return sb.toString();
    }

    private static String parseSignatureAlgorithmsExtension(byte[] data) {
        StringBuilder sb = new StringBuilder();

        // Signature Hash Algorithms Length
        int signatureLength = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        sb.append(String.format("\tSignature Hash Algorithms Length: %d\n", signatureLength));

        if (signatureLength > 0) {
            sb.append(String.format("\tSignature Hash Algorithms (%d algorithms)\n", signatureLength/2));
        }

        int i = 2;
        while (i < data.length) {

            int hash = data[i] & 0xff;
            int signature = data[i+1] & 0xff;
            int signatureAlgo = (hash << 8) | signature;
            sb.append(String.format("\t* Signature Algorithm: 0x%04x\n", signatureAlgo));
            sb.append(String.format("\t\tSignature Hash Algorithm Hash: %s (%d)\n", getHash(hash), hash));
            sb.append(String.format("\t\tSignature Hash Algorithm Signature: %s (%d)\n", getSignature(signature), signature));
            i+=2;
        }
        return sb.toString();
    }

    private static String getHash(int id) {
        return switch (id) {
            case 1 -> "MD5";
            case 2 -> "SHA1";
            case 3 -> "SHA224";
            case 4 -> "SHA256";
            case 5 -> "SHA384";
            case 6 -> "SHA512";
            default -> "Unknown";
        };
    }

    private static String getSignature(int id) {
        return switch (id) {
            case 1 -> "RSA";
            case 2 -> "DSA";
            case 3 -> "ECDSA";
            case 4 -> "SM2";
            default -> "Unknown";
        };
    }

    private static String parsePskKeyExchangeModesExtension(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int length = data[0] & 0xff;
        sb.append(String.format("\tPSK Key Exchange Modes Length: %d\n", length));
        // Mode list
        for (int i=1; i <= length; i++) {
            int mode = data[i];
            sb.append(String.format("\tPSK Key Exchange Mode: 0x%02x\n", mode));
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

    // Helper to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x ", b));
        }
        return hex.toString().trim();
    }

    private static String getGroupValue(int id) {
        switch (id) {
            case 0x001d:
                return "x25519";
            case 0x0017:
                return "secp256r1";
            case 0x001e:
                return "x448";
            case 0x0019:
                return "secp521r1";
            case 0x0018:
                return "secp384r1";
            case 0x0100:
                return "ffdhe2048";
            case 0x0101:
                return "ffdhe3072";
            case 0x0102:
                return "ffdhe4096";
            case 0x0103:
                return "ffdhe6144";
            case 0x0104:
                return "ffdhe8192";
            default:
                return String.format("unknown (0x%04x)", id);
        }
    }
}