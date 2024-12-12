package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Hashtable;

public class BCServer {

    private static final int SERVER_PORT = 1238;

    private static final ProtocolVersion[] S_TLS_VERSIONS = new ProtocolVersion[]{ProtocolVersion.TLSv13};
    private static final int[] S_CIPHER_SUITES = new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256};

    public static void main(String[] args) throws Exception {

        // Secure random number generator
        SecureRandom secureRandom = new SecureRandom();

        // Set up the server socket to listen on port 1238
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        System.out.println("TLS Server listening on port " + SERVER_PORT);

        // Accept incoming client connections
        Socket socket = serverSocket.accept();
        System.out.println("Connection established with client");

        // Create the TLS server protocol handler
        TlsServerProtocol protocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
        // Create a custom server instance by subclassing DefaultTlsServer
        TlsServer server = new DefaultTlsServer(new BcTlsCrypto()) {

            @Override
            public ProtocolVersion[] getProtocolVersions() {
                return S_TLS_VERSIONS;
            }

            @Override
            protected int[] getSupportedCipherSuites() {
                return S_CIPHER_SUITES;
            }

            @Override
            public Hashtable getServerExtensions() throws IOException {
                // You can customize server extensions here if necessary.
                return super.getServerExtensions();
            }
        };

        // Perform the TLS handshake
        try {
            protocol.accept(server);

            // Read the HTTP request sent by the client over the TLS connection
            InputStream inputStream = protocol.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Received: " + line);
            }

            // Send HTTP response back to the client
            OutputStream outputStream = protocol.getOutputStream();
            outputStream.write("HTTP/1.1 200 OK\r\n".getBytes("UTF-8"));
            outputStream.write("Content-Type: text/plain\r\n".getBytes("UTF-8"));
            outputStream.write("Connection: close\r\n".getBytes("UTF-8"));
            outputStream.write("\r\n".getBytes("UTF-8"));
            outputStream.write("Hello, this is a secure TLS server!\r\n".getBytes("UTF-8"));
            outputStream.flush();

            // Close the socket connection
            socket.close();
            serverSocket.close();
            System.out.println("Connection closed");

        } catch (Exception e) {
            System.out.println("Error in client connection");
            e.printStackTrace();
        }
    }
}
