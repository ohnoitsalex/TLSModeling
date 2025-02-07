package application.system_under_test.tls_system_under_test;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;

public class Client {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();

    public static void main(String[] args) throws IOException {

        // signature_algorithms
        Vector<SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
        signature_algorithms.addElement(SignatureAndHashAlgorithm.ed448);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
        signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);

        // supportedGroup
        Vector<Integer> supported_groups = new Vector<>();
        supported_groups.addElement(NamedGroup.x25519);
        supported_groups.addElement(NamedGroup.x448);


        // key_share
        Vector<Integer> key_share = new Vector<Integer>();
        key_share.addElement(NamedGroup.x448);


        sendClientHello(new ProtocolVersion[]{ProtocolVersion.TLSv13},
                new int[]{CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA,CipherSuite.TLS_AES_256_GCM_SHA384},
                signature_algorithms,
                supported_groups, key_share,
                new ProtocolVersion[]{ProtocolVersion.TLSv13});
    }

    public static void sendClientHello(ProtocolVersion[] tlsVersions, int[] ciphers,
                                       Vector<SignatureAndHashAlgorithm> signatureAlgorithms,
                                       Vector<Integer> supportedGroup,
                                       Vector<Integer> keyShare,
                                       ProtocolVersion[] protocolVersion) throws IOException {

        // CLIENT CREATION

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
                return tlsVersions;
            }

            //Cipher Suites Entries
            @Override
            protected int[] getSupportedCipherSuites() {
                return ciphers;
            }

            @Override
            public TlsAuthentication getAuthentication() throws IOException {
                return null;
            }

            //Signature Algorithms Entries Entries
            @Override
            protected Vector getSupportedSignatureAlgorithms() {
                return signatureAlgorithms;
            }

            //Supported Groups Entries
            @Override
            protected Vector getSupportedGroups(Vector vector) {
                return supportedGroup;
            }

//            @Override
//            protected short[] getAllowedServerCertificateTypes() {
//                return super.getAllowedServerCertificateTypes();
//            }

            //Key Share Entries
            @Override
            public Vector getEarlyKeyShareGroups() {
                return keyShare;
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
//                return ProtocolVersion.TLSv13.downTo(ProtocolVersion.TLSv13);
                return protocolVersion;
            }
        };

        protocol.initConnexion(client);

        protocol.sendClientHello();

        protocol.concludeClientHello();

        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            // Send a message to the server
            out.println("Hello, Server!");

            // Read the response from the server
            String response = in.readLine();
            System.out.println("Received from server: " + response);
        }

    }

//
//    public static void main(String[] args) {
//        try {
//            // Create trust manager that trusts all certificates
//            TrustManager[] trustManagers = new TrustManager[]{
//                    new X509TrustManager() {
//                        @Override
//                        public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
//                                throws CertificateException {
//                        }
//
//                        @Override
//                        public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
//                                throws CertificateException {
//                        }
//
//                        @Override
//                        public X509Certificate[] getAcceptedIssuers() {
//                            return new X509Certificate[0];
//                        }
//                    }
//            };
//
//            // Create SSL context
//            SSLContext sslContext = SSLContext.getInstance("TLS");
//            sslContext.init(null, trustManagers, new SecureRandom());
//
//            // Create SSL socket factory
//            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
//
//            // Create SSL socket
//            try (SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_HOST, SERVER_PORT)) {
//                // Enable custom cipher suites
//                String[] customCipherSuites = {
//                        "TLS_RSA_WITH_AES_256_CBC_SHA",
//                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
//                };
//                //socket.setEnabledCipherSuites(customCipherSuites);
//                //socket.setEnabledProtocols(new String[]{"TLSv1.3"});
//
//                try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
//                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
//
//                    // Send a message to the server
//                    out.println("Hello, Server!");
//
//                    // Read the response from the server
//                    String response = in.readLine();
//                    System.out.println("Received from server: " + response);
//                }
//            }
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
}
