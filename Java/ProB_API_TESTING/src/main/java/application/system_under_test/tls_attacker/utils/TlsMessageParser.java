package application.system_under_test.tls_attacker.utils;

import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import java.util.HashMap;
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
        data.put("protocol_version", message.getProtocolVersion().getValue().toString());
        data.put("random", message.getRandom().getValue().toString());
        data.put("session_id", message.getSessionId().getValue().toString());
        data.put("selected_cipher_suite", message.getSelectedCipherSuite().getValue().toString());
        data.put("selected_compression_method", message.getSelectedCompressionMethod().getValue().toString());
        
        return data;
    }
}
