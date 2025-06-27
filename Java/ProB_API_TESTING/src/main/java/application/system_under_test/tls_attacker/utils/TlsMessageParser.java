package application.system_under_test.tls_attacker.utils;

import static application.system_under_test.tls_attacker.utils.ByteUtils.bytesToHex;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Utility class for parsing TLS messages.
 */
public class TlsMessageParser {
    
    /**
     * Parses a ServerHelloMessage into a map of key-value pairs.
     * @param message The ServerHelloMessage to parse
     * @return Map containing the parsed data
     */
    public static Map<String, String> parseServerHello(ServerHelloMessage message) {
        Map<String, String> data = new HashMap<>();
        
        // Parse basic fields
        data.put("protocol_version", bytesToHex(message.getProtocolVersion().getValue()));
        data.put("random", bytesToHex(message.getRandom().getValue()));
        data.put("session_id", bytesToHex(message.getSessionId().getValue()));
        data.put("selected_cipher_suite", bytesToHex(message.getSelectedCipherSuite().getValue()));
        data.put("selected_compression_method", bytesToHex(new byte[] { message.getSelectedCompressionMethod().getValue() }));
        
        return data;
    }

    /**
     * Parses a ClientHelloMessage into a map of key-value pairs.
     * @param message The ClientHelloMessage to parse
     * @return Map containing the parsed data
     */
    public static Map<String, String> parseClientHello(ClientHelloMessage message) {
    Map<String, String> map = new LinkedHashMap<>();

        map.put("random", bytesToHex(message.getRandom().getValue()));
        map.put("protocol_version", bytesToHex(message.getProtocolVersion().getValue()));
        map.put("session_id", bytesToHex(message.getSessionId().getValue()));
        map.put("cipher_suites", bytesToHex(message.getCipherSuites().getValue()));
        map.put("compression_methods", bytesToHex(message.getCompressions().getValue()));


        return map;
}

}
