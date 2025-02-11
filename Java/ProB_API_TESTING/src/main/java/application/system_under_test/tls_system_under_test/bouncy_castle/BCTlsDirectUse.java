package application.system_under_test.tls_system_under_test.bouncy_castle;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Vector;

public class BCTlsDirectUse {

    // Client default parameter
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();
    private static final Vector<Integer> supported_groups = new Vector<Integer>();
    private static final Vector<Integer> key_share = new Vector<Integer>();

    public static void sendClientHello(ProtocolVersion[] tlsVersions, int[] ciphers,
                                       Vector <SignatureAndHashAlgorithm> signatureAlgorithms,
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

            //KEEPING JUST IN CASE
            @Override
            protected Vector getSupportedSignatureAlgorithmsCert() {
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.ed448);
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                signature_algorithms_cert.addElement(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
                return signature_algorithms_cert;
            }

            @Override
            protected ProtocolVersion[] getSupportedVersions() {
                return protocolVersion;
            }
        };

        protocol.initConnexion(client);

        protocol.sendClientHello();

        protocol.concludeClientHello();
    }
//   FOR FURTHER IMPLEMENTATIONS
//    public static void sendServerHello() {
//
//    }
}
