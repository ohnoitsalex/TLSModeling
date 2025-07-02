package application.system_under_test.tls_attacker.utils;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
// import de.rub.nds.tlsattacker.core.constants.NamedGroup;
// import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
// import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Utility class for building TLS message components.
 */
public class TlsMessageBuilder {
    
    /**
     * Builds a SupportedVersionsExtensionMessage from YAML data.
     * @param data The YAML data containing supported_versions field
     * @return The built extension message
     */
    public static SupportedVersionsExtensionMessage buildSupportedVersions(Map<String, String> data) {
        SupportedVersionsExtensionMessage versions = new SupportedVersionsExtensionMessage();
        List<Byte> versionBytes = new ArrayList<>();

        String versionsStr = data.get("supported_versions");

        if (versionsStr != null && !versionsStr.isEmpty()) {
            versionsStr = versionsStr.replaceAll("[{}\\[\\]]", "");
            String[] versionArray = versionsStr.split(",");

            for (String version : versionArray) {
                ProtocolVersion pv = switch (version.trim()) {
                    case "TLS_1_3" -> ProtocolVersion.TLS13;
                    case "TLS_1_2" -> ProtocolVersion.TLS12;
                    case "TLS_1_1" -> ProtocolVersion.TLS11;
                    case "TLS_1_0" -> ProtocolVersion.TLS10;
                    default -> {
                        System.err.println("TLS version not recognized: " + version.trim());
                        yield null;
                    }
                };

                if (pv != null) {
                    byte[] raw = pv.getValue(); // 2-byte version value
                    versionBytes.add(raw[0]);
                    versionBytes.add(raw[1]);
                }
            }
        }

        if (versionBytes.isEmpty()) {
            byte[] fallback = ProtocolVersion.TLS13.getValue();
            versionBytes.add(fallback[0]);
            versionBytes.add(fallback[1]);
        }

        byte[] result = new byte[versionBytes.size()];
        for (int i = 0; i < versionBytes.size(); i++) {
            result[i] = versionBytes.get(i);
        }

        versions.setSupportedVersions(result);
        return versions;
    }

    /**
     * Builds a SignatureAndHashAlgorithmsExtensionMessage from YAML data.
     * @param data The YAML data
     * @return The built extension message
     */
    public static SignatureAndHashAlgorithmsExtensionMessage buildSignatureAlgorithms(Map<String, String> data) {
        SignatureAndHashAlgorithmsExtensionMessage sigHash = new SignatureAndHashAlgorithmsExtensionMessage();
        List<Byte> sigBytes = new ArrayList<>();

        String algoStr = data.get("signature_algorithms");

        if (algoStr != null && !algoStr.isEmpty()) {
            algoStr = algoStr.replaceAll("[{}\\[\\]]", "");
            String[] algoArray = algoStr.split(",");

            for (String algo : algoArray) {
                SignatureAndHashAlgorithm scheme = switch (algo.trim()) {
                    case "rsa_pss_rsae_sha512"     -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;
                    case "rsa_pss_rsae_sha256"     -> SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256;
                    case "ecdsa_secp256r1_sha256"  -> SignatureAndHashAlgorithm.ECDSA_SHA256;
                    case "ecdsa_secp384r1_sha384"  -> SignatureAndHashAlgorithm.ECDSA_SHA384;
                    case "ed25519"                 -> SignatureAndHashAlgorithm.ED25519;
                    default -> {
                        System.err.println("Signature algorithm not recognized: " + algo.trim());
                        yield null;
                    }
                };

                if (scheme != null) {
                    sigBytes.add((byte)scheme.getSignatureAlgorithm().ordinal());
                    sigBytes.add((byte)scheme.getHashAlgorithm().ordinal());
                }
            }
        }

        if (sigBytes.isEmpty()) {
            SignatureAndHashAlgorithm defaultScheme = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;
            sigBytes.add((byte)defaultScheme.getSignatureAlgorithm().ordinal());
            sigBytes.add((byte)defaultScheme.getHashAlgorithm().ordinal());
        }

        byte[] result = new byte[sigBytes.size()];
        for (int i = 0; i < sigBytes.size(); i++) {
            result[i] = sigBytes.get(i);
        }

        sigHash.setSignatureAndHashAlgorithms(result);
        return sigHash;
    }


    /**
     * Builds a KeyShareExtensionMessage from YAML data.
     * @param data The YAML data
     * @return The built extension message
     */
    public static KeyShareExtensionMessage buildKeyShare(Map<String, String> data) {
        KeyShareExtensionMessage keyShare = new KeyShareExtensionMessage();
        List<KeyShareEntry> entries = new ArrayList<>();

        String groupStr = data.getOrDefault("key_share_group", "x25519").trim();

        NamedGroup group = switch (groupStr.toLowerCase()) {
            case "x25519"     -> NamedGroup.ECDH_X25519;
            case "x448"       -> NamedGroup.ECDH_X448;
            case "secp256r1"  -> NamedGroup.SECP256R1;
            case "secp384r1"  -> NamedGroup.SECP384R1;
            default -> {
                System.err.println("Unknown group : " + groupStr + " — fallback on x25519");
                yield NamedGroup.ECDH_X25519;
            }
        };

        int keyLength = switch (group) {
            case ECDH_X25519 -> 32;
            case ECDH_X448   -> 56;
            case SECP256R1   -> 65; // Uncompressed EC point (0x04 + X + Y)
            case SECP384R1   -> 97;
            default          -> 32;
        };

        // Generate a fake public key 
        byte[] publicKey = new byte[keyLength];
        new SecureRandom().nextBytes(publicKey);

        // Create the typed KeyShareEntry
        KeyShareEntry entry = new KeyShareEntry();
        entry.setGroupConfig(group);
        entry.setPublicKey(publicKey);

        entries.add(entry);
        keyShare.setKeyShareList(entries);

        return keyShare;
    }


    /**
     * Builds a list of CipherSuite from YAML data.
     * @param data The YAML data
     * @return List of cipher suites
     */
    public static List<CipherSuite> buildCipherSuites(Map<String, String> data) {
        List<CipherSuite> suites = new ArrayList<>();
        String cipherSuitesStr = data.get("cipher_suites");
        if (cipherSuitesStr != null && !cipherSuitesStr.isEmpty()) {
            // Parse and add cipher suites
            suites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        }
        return suites;
    }

    /**
     * Builds a list of NamedGroup from YAML data.
     * @param data The YAML data
     * @return List of named groups
     */
    public static List<NamedGroup> buildNamedGroups(Map<String, String> data) {
        List<NamedGroup> groups = new ArrayList<>();
        String groupsStr = data.get("supported_groups");
        if (groupsStr != null && !groupsStr.isEmpty()) {
            // Parse and add named groups
            groups.add(NamedGroup.SECP256R1);
        }
        return groups;
    }


    /**
     * Builds a ClientHelloMessage from YAML data.
     * @param clientHelloMap The YAML data containing client hello fields
     * @param clientHello The ClientHelloMessage to build
     * @param config The TLS configuration
     */
    public static void buildClientHello(Map<String, String> clientHelloMap ,ClientHelloMessage clientHello, Config config) {
        // Build and add Supported Versions extension
        SupportedVersionsExtensionMessage versions = buildSupportedVersions(clientHelloMap);
        clientHello.addExtension(versions);

        // Build and add Signature Algorithms extension
        SignatureAndHashAlgorithmsExtensionMessage sigHash = buildSignatureAlgorithms(clientHelloMap);
        clientHello.addExtension(sigHash);

        // Build and add Key Share extension
        KeyShareExtensionMessage keyShare = buildKeyShare(clientHelloMap);
        clientHello.addExtension(keyShare);

        // Build and set Cipher Suites
        List<CipherSuite> suites = buildCipherSuites(clientHelloMap);
        config.setDefaultClientSupportedCipherSuites(suites);

        // Build and set Supported Groups
        List<NamedGroup> groups = buildNamedGroups(clientHelloMap);
        config.setDefaultClientNamedGroups(groups);

    }


    /**
     * Builds a ServerHelloMessage from YAML data.
     * @param serverHelloMap The YAML data containing server hello fields
     * @param serverHello The ServerHelloMessage to build
     * @param config The TLS configuration
     */
    public static void buildServerHello(Map<String, String> serverHelloMap, ServerHelloMessage serverHello, Config config){
        // TODO: Implement server hello message building logic
        throw new UnsupportedOperationException("ServerHello message building not yet implemented");
        

    }

}