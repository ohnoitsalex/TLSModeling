package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.checkerframework.checker.units.qual.Length;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

public class BCServer {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1238;
    private static final Vector<SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();
    private static final Vector<Integer> key_share = new Vector<Integer>();
    private static final ProtocolVersion[] tls_versions = new ProtocolVersion[]{ProtocolVersion.TLSv13};
    private static final int[] enabled_cipher_suites = new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256};

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

            //Protocol Version Entries
            @Override
            public ProtocolVersion[] getProtocolVersions() {
                return tls_versions;
            }

            //Cipher Suites Entries
            @Override
            protected int[] getSupportedCipherSuites() {
                return enabled_cipher_suites;
            }

            @Override
            public Hashtable getServerExtensions() {

                Hashtable extensions = new Hashtable();
                try {
                    // Signature Algorithms
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.ed448);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);

                    TlsExtensionsUtils.addSignatureAlgorithmsExtension(extensions, signature_algorithms);

                    // Signature Algorithm Certificates
                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.ed448);
                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);

                    TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(extensions, signature_algorithms_cert);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return extensions;
            }

            //Supported Groups Entries
            @Override
            public int[] getSupportedGroups() {
                return new int[]{NamedGroup.x448};
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
