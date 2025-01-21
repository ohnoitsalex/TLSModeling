package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.checkerframework.checker.units.qual.Length;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Vector;


public class BCServer {


    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static final Vector<SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();
    private static final Vector<Integer> key_share = new Vector<Integer>();
    private static final ProtocolVersion[] tls_versions = new ProtocolVersion[]{ProtocolVersion.TLSv13};
    private static final int[] enabled_cipher_suites = new int[]{CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256};


    public static void main(String[] args) throws Exception {


        // Set up the server socket to listen on port 1238
        ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
        System.out.println("TLS Server listening on port " + SERVER_PORT);


        // Accept incoming client connections
        Socket socket = serverSocket.accept();
        System.out.println("Connection established with client");


        // Create the TLS server protocol handler
        TlsServerProtocol protocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream());
        // Create a custom server instance by subclassing DefaultTlsServer
        BcTlsCrypto crypto = new BcTlsCrypto();
        TlsServer server = new DefaultTlsServer(crypto) {
            //Protocol Version Entries
            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return ProtocolVersion.TLSv13.only();
            }


            //Cipher Suites Entries
            @Override
            protected int[] getSupportedCipherSuites() {
                return enabled_cipher_suites;
            }


//            @Override
//            public Hashtable getServerExtensions() {
//
//                Hashtable extensions = new Hashtable();
//                try {
//                    // Signature Algorithms
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.ed448);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha256);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha384);
//                    signature_algorithms.addElement(SignatureAndHashAlgorithm.rsa_pss_pss_sha512);
//
//                    TlsExtensionsUtils.addSignatureAlgorithmsExtension(extensions, signature_algorithms);
//
//                    // Signature Algorithm Certificates
//                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.ed448);
//                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
//                    signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
//
//                    TlsExtensionsUtils.addSignatureAlgorithmsCertExtension(extensions, signature_algorithms_cert);
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//                return extensions;
//            }


            @Override
            public TlsCredentials getCredentials() throws IOException {
                try {
                    CertificateHandler.generate();
//                    // Loading private key from file
//                    System.out.println(new FileInputStream("src/main/resources/session/private_key.pem"));
//                    byte[] keyBytes = Files.readAllBytes(Path.of("src/main/resources/session/private_key.pem"));
//                    String test = new String(keyBytes, StandardCharsets.UTF_8);
//                    System.out.println(test);
//                    AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(keyBytes);

                    //Loading private key from api
                    AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(CertificateHandler.keyPair.getPrivate().getEncoded());

//                    // Loading certificate from file
//                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
//                    Certificate cert = cf.generateCertificate(new FileInputStream("src/main/resources/session/certificate.crt"));
//                    BcTlsCertificate bcCert = new BcTlsCertificate(crypto, cert.getEncoded());
//                    org.bouncycastle.tls.Certificate tlsCert = new org.bouncycastle.tls.Certificate(new BcTlsCertificate[]{bcCert});

                    org.bouncycastle.tls.Certificate tlsCertificate = new org.bouncycastle.tls.Certificate(
                            new org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate[]{new org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate(crypto, CertificateHandler.certificate.getEncoded())});




//                    // Créer les informations d'identité du serveur
//                    return new BcDefaultTlsCredentialedSigner(
//                            new TlsCryptoParameters(context),
//                            crypto,
//                            privateKey,
//                            tlsCertificate,
//                            SignatureAndHashAlgorithm.rsa_pss_pss_sha256
//                                        );
                    return null;

                } catch (Exception e) {
                    throw new IOException("Échec du chargement des informations d'identité", e);
                }
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
            outputStream.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.UTF_8));
            outputStream.write("Content-Type: text/plain\r\n".getBytes(StandardCharsets.UTF_8));
            outputStream.write("Connection: close\r\n".getBytes(StandardCharsets.UTF_8));
            outputStream.write("\r\n".getBytes(StandardCharsets.UTF_8));
            outputStream.write("Hello, this is a secure TLS server!\r\n".getBytes(StandardCharsets.UTF_8));
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
