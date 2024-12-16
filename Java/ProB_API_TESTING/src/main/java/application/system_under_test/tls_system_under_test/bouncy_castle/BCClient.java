package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.TlsCrypto;

import java.io.*;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Vector;

public class BCClient {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1238;
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();
    private static final Vector<Integer> supported_groups = new Vector<Integer>();
    private static final Vector<Integer> key_share = new Vector<Integer>();
    private static final ProtocolVersion[] C_TLS_VERSIONS = new ProtocolVersion[]{ProtocolVersion.TLSv12, ProtocolVersion.TLSv13};
    private static final int[] C_CIPHERS = new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256};


    public static void main(String[] args) throws Exception {
        // Secure random number generator
        SecureRandom secureRandom = new SecureRandom();

        // Establish the socket connection to the server
        Socket socket = new Socket(SERVER_HOST, SERVER_PORT);

        // Create the TLS client protocol using Bouncy Castle's crypto implementation
        TlsClientProtocol protocol = new TlsClientProtocol(socket.getInputStream(), socket.getOutputStream());
        TlsClient client = new DefaultTlsClient(new BcTlsCrypto()) {

            //Protocol Version Entries
            @Override
            public ProtocolVersion[] getProtocolVersions() {
                return C_TLS_VERSIONS;
            }

            //Cipher Suites Entries
            @Override
            protected int[] getSupportedCipherSuites() {
                return C_CIPHERS;
            }

            @Override
            public TlsAuthentication getAuthentication() throws IOException {
                return null;
            }

            //Signature Algorithms Entries
            @Override
            protected Vector getSupportedSignatureAlgorithms() {
                signature_algorithms.addElement(SignatureAndHashAlgorithm.ed448);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
                signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);
                return signature_algorithms;
            }

//            //Supported Groups Entries
            @Override
            protected Vector getSupportedGroups(Vector vector) {
                supported_groups.addElement(NamedGroup.x25519);
                supported_groups.addElement(NamedGroup.x448);
                return supported_groups;
            }

            @Override
            protected short[] getAllowedServerCertificateTypes() {
                return super.getAllowedServerCertificateTypes();
            }

            //Key Share Entries
            @Override
            public Vector getEarlyKeyShareGroups() {
                //key_share.addElement(NamedGroup.x25519);
                key_share.addElement(NamedGroup.x448);
                return key_share;
            }

            @Override
            protected Vector getSupportedSignatureAlgorithmsCert() {
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.ed448);
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
                return signature_algorithms_cert;
            }

            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv13);
            }
        };

        //TRYING TO REPRODUCE 2 CLIENTHELLO B2B

//        // Create the first Runnable for startCapture
//        Runnable start_connection = new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    protocol.connect(client);
//                } catch (IOException e) {
//                    throw new RuntimeException(e);
//                }
//            }
//        };
//
//        // Create two threads for each task - It takes a bit of time before the .txt file is generated.
//        Thread thread1 = new Thread(start_connection);
//        Thread thread2 = new Thread(start_connection);
//
//        // Start the threads
//        thread1.start();
//        thread2.start();

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
