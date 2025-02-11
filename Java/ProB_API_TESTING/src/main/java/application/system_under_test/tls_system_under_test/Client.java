package application.system_under_test.tls_system_under_test;

import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

public class Client {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();

    public static Map<String, String> parseYaml(String filePath) throws IOException {
        List<String> lines = Files.readAllLines(Paths.get(filePath));
        return lines.stream()
                .filter(line -> line.contains(":"))
                .map(line -> line.split(":", 2))
                .collect(Collectors.toMap(arr -> arr[0].trim(), arr -> arr[1].trim().replace("'", "")));
    }

    public static void main(String[] args) throws IOException {

        try {
            Map<String, String> clientHelloInfo = parseYaml("src/main/resources/data/ModelClientHello.yaml");

            ProtocolVersion[] tls_versions = Arrays.stream(getExtensionData(clientHelloInfo, "supported_versions"))
                            .map(Client::getProtocolVersionFromString)
                            .toArray(ProtocolVersion[]::new);

            int[] cipher_suites = Arrays.stream(getExtensionData(clientHelloInfo, "cipher_suites"))
                    .mapToInt(Client::getCipherSuiteFromString)
                    .toArray();

            Vector<SignatureAndHashAlgorithm> signature_algorithms = new Vector<>();
            for (String algo : getExtensionData(clientHelloInfo, "signature_algorithms")) {
                signature_algorithms.add(getSignatureAlgorithmFromString(algo));
            }


            Vector<Integer> supported_groups = new Vector<>();
            for (String group : getExtensionData(clientHelloInfo, "supported_groups")) {
                supported_groups.add(getNamedGroupFromString(group));
            }

            Vector<Integer> key_share = new Vector<>();
            for (String key : getExtensionData(clientHelloInfo, "pre_shared_key")) {
                key_share.add(getNamedGroupFromString(key));
            }

            ProtocolVersion[] protocol_versions = Arrays.stream(getExtensionData(clientHelloInfo, "supported_versions"))
                    .map(Client::getProtocolVersionFromString)
                    .toArray(ProtocolVersion[]::new);


            sendClientHello(tls_versions, cipher_suites, signature_algorithms, supported_groups, key_share, protocol_versions);

        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("Error while reading client parameters");
        }

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
                return protocolVersion;
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
                return tlsVersions;
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


    public static ProtocolVersion getProtocolVersionFromString(String version) {
         switch (version) {
            case "SSL_3_0": return ProtocolVersion.SSLv3;
            case "TLS_1_0": return ProtocolVersion.TLSv10;
            case "TLS_1_1": return ProtocolVersion.TLSv11;
            case "TLS_1_2": return ProtocolVersion.TLSv12;
            case "TLS_1_3": return ProtocolVersion.TLSv13;
            case "DTLS_1_0": return ProtocolVersion.DTLSv10;
            case "DTLS_1_2": return ProtocolVersion.DTLSv12;
            case "DTLS_1_3": return ProtocolVersion.DTLSv13;
            default: throw new IllegalArgumentException("Unknown Protocol Version: " + version);
        }
    }

    public static int getCipherSuiteFromString(String cipher) {
        try {
            return (int) CipherSuite.class.getField(cipher).get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalArgumentException("Unknown Cipher Suite: " + cipher, e);
        }
    }

    public static SignatureAndHashAlgorithm getSignatureAlgorithmFromString(String algo) {
        try {
            return (SignatureAndHashAlgorithm) SignatureAndHashAlgorithm.class.getField(algo).get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalArgumentException("Unknown Signature Algorithm: " + algo, e);
        }
    }

    public static int getNamedGroupFromString(String group) {
        try {
            return (int) NamedGroup.class.getField(group.toLowerCase()).get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IllegalArgumentException("Unknown Named Group: " + group, e);
        }
    }

    public static String[] getExtensionData(Map<String, String> clientAllInfos, String attribute) {
        String[] data = clientAllInfos.get(attribute).replace("{", "").replace("}", "").split(",");
        if (data.length == 1 & Objects.equals(data[0], "")) {
            data = new String[]{};
        } else {
            data = Arrays.stream(data).map(String::trim).toArray(String[]::new);
        }
        return data;

    }
}
