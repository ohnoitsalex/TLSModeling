package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCrypto;

import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;

public class BCClient {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1238;

    public static void main(String[] args) throws Exception {
        // Secure random number generator
        SecureRandom secureRandom = new SecureRandom();

        // Establish the socket connection to the server
        Socket socket = new Socket(SERVER_HOST, SERVER_PORT);

        // Create the TLS client protocol using Bouncy Castle's crypto implementation
        TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
        TlsClient client = new DefaultTlsClient(new BcTlsCrypto()) {
            @Override
            public TlsAuthentication getAuthentication() throws IOException {
                return null;
            }
        };

        // Start the TLS handshake
        protocol.connect(client);

        // Send an HTTP request over the TLS connection (this is the application data)
        OutputStream outputStream = protocol.getOutputStream();
        outputStream.write("GET / HTTP/1.1\r\n".getBytes("UTF-8"));
        outputStream.write("Host: localhost\r\n".getBytes("UTF-8"));
        outputStream.write("Connection: close\r\n".getBytes("UTF-8"));
        outputStream.write("\r\n".getBytes("UTF-8"));
        outputStream.flush();

        // Read the server's response
        InputStream inputStream = protocol.getInputStream();
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }

        // Close the connection
        socket.close();
    }
}
