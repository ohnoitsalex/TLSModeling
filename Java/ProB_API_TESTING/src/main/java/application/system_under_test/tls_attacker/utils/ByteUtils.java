package application.system_under_test.tls_attacker.utils;



/**
 * Utility class for converting byte arrays to hexadecimal strings.
 */
public class ByteUtils {

    /**
     * Converts a byte array to a hexadecimal string.
     * @param bytes
     * @return String containing the hexadecimal representation of the byte array
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }
}
