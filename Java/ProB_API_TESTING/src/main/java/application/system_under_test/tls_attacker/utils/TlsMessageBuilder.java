package application.system_under_test.tls_attacker.utils;

import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import java.util.Map;

public class TlsMessageBuilder {
    public static ClientHelloMessage buildClientHello(Map<String, String> params) {
        ClientHelloMessage message = new ClientHelloMessage();
        // Configure the message based on params
        return message;
    }
}
