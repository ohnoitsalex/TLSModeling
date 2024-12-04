package application.system_under_test.tls_system_under_test;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class Server {
    private static final int PORT = 1238;
    public static void main(String[] args) {
        try {
            // Load keystore containing server's private key and certificate
            char[] password = "test123".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream("/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/session/serverkeystore")) {
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

//
//    private String[] protocols;
//    private String[] cipherSuites;
//
//    public Server (String[] protocols, String[] cipherSuites){
//        this.protocols = protocols;
//        this.cipherSuites = cipherSuites;
//    }
//    public void startServer() throws Exception {
//
//        SSLServerSocket serverSocket = null;
//
//        try {
//
//            // Step : 1
//            SSLServerSocketFactory factory =
//                    (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
//
//            // Step : 2
//            serverSocket = (SSLServerSocket) factory.createServerSocket(8980);
//
//            // Step : 3
//            serverSocket.setEnabledProtocols(protocols);
//            serverSocket.setEnabledCipherSuites(cipherSuites);
//
//            // Step : 4
//            SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
//
//            // Step : 5
//            InputStream inputStream = sslSocket.getInputStream();
//            InputStreamReader inputStreamReader = new
//                    InputStreamReader(inputStream);
//
//            BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
//            String request = null;
//            while((request = bufferedReader.readLine()) != null) {
//                System.out.println(request);
//                System.out.flush();
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        } finally {
//            if (serverSocket != null) {
//                serverSocket.close();
//            }
//        }
//    }
}
