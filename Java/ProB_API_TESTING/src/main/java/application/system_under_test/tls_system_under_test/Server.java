package application.system_under_test.tls_system_under_test;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;

public class Server {
    private static final int PORT = 1234;

    public static void main(String[] args) {
        try {
            // Load keystore containing server's private key and certificate
            char[] password = "test123".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream("src/main/resources/session/serverkeystore")) {
                keyStore.load(fis, password);
            }

            // Create key manager factory
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, password);

            // Create SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            // Create SSL server socket factory
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

            // Create SSL server socket
            try (SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT)) {
                System.out.println("Server started. Waiting for client...");

                // Enable custom cipher suites
                String[] customCipherSuites = {
                };
                //serverSocket.setEnabledCipherSuites(customCipherSuites);
                // Specify allowed TLS versions
                //serverSocket.setEnabledProtocols(new String[]{"TLSv1.3"});

                // Accept incoming connections
                try (SSLSocket clientSocket = (SSLSocket) serverSocket.accept()) {
                    System.out.println("Client connected.");

                    // Perform communication with client
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                         PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {

                        String message;
                        while ((message = in.readLine()) != null) {
                            System.out.println("Received from client: " + message);
                            out.println("Server received: " + message);
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
