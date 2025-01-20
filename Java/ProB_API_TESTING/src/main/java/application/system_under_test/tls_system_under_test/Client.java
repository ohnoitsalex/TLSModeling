package application.system_under_test.tls_system_under_test;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Client {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1238;

    public static void main(String[] args) {
        try {
            // Create trust manager that trusts all certificates
            TrustManager[] trustManagers = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
                                throws CertificateException {
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
                                throws CertificateException {
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
            };

            // Create SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, new SecureRandom());

            // Create SSL socket factory
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            // Create SSL socket
            try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_HOST, SERVER_PORT)) {
                // Enable custom cipher suites
                String[] customCipherSuites = {
                        "TLS_RSA_WITH_AES_256_CBC_SHA",
                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
                };
                socket.setEnabledCipherSuites(customCipherSuites);
                socket.setEnabledProtocols(new String[]{"TLSv1.2"});

                try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

                    // Send a message to the server
                    out.println("Hello, Server!");

                    // Read the response from the server
                    String response = in.readLine();
                    System.out.println("Received from server: " + response);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
