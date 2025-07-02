package application.information_holder.tls_information_holder;

import application.information_handler.InformationConvertertoAbstract;

import java.util.HashMap;
import java.util.Map;

/**
 * Information holder for TLS ServerHello message data.
 * This class stores and manages all relevant information extracted from ServerHello messages
 * during TLS handshake testing, providing standardized access to server-side handshake parameters.
 * 
 * <p>The stored information includes:
 * <ul>
 *   <li>Server random value</li>
 *   <li>Protocol version information (legacy and supported versions)</li>
 *   <li>Session ID echo and compression methods</li>
 *   <li>Cipher suite selection and key exchange parameters</li>
 *   <li>Extension data (pre-shared keys, key shares)</li>
 * </ul>
 * 
 */
public class TLSServerInformationHolder {

    // Create a HashMap
    private static Map<String, String> serverHelloInformation = new HashMap<>();

    /**
     * Default constructor that initializes all ServerHello fields to null.
     * Creates a HashMap with standard TLS ServerHello message fields ready for population.
     */
    public TLSServerInformationHolder(){
        serverHelloInformation.put("random", null);
        serverHelloInformation.put("legacy_version", null);
        serverHelloInformation.put("supported_versions",null);
        serverHelloInformation.put("legacy_compression_methods",null);
        serverHelloInformation.put("pre_shared_key",null);
        serverHelloInformation.put("legacy_session_id_echo",null);
        serverHelloInformation.put("key_share",null);
        serverHelloInformation.put("cipher_suites",null);
    }

    /**
     * Updates all ServerHello information fields in a single operation.
     * This method provides a convenient way to populate all ServerHello fields at once.
     * 
     * @param random the server's random value for this handshake
     * @param legacy_version the legacy version field (typically 0x0303 for TLS 1.2)
     * @param supported_versions the list of supported TLS versions
     * @param legacy_compression_methods the compression methods (typically null/0 for TLS 1.3)
     * @param pre_shared_key pre-shared key extension data
     * @param legacy_session_id_echo the session ID echo from the client
     * @param key_share key share extension data for key exchange
     * @param cipher_suites the selected cipher suite for this connection
     */
    public void updateServerHelloInformation(String random, String legacy_version, String supported_versions, String legacy_compression_methods,
                                             String pre_shared_key, String legacy_session_id_echo, String key_share,
                                             String cipher_suites){
        serverHelloInformation.put("random", random);
        serverHelloInformation.put("legacy_version", legacy_version);
        serverHelloInformation.put("supported_versions",supported_versions);
        serverHelloInformation.put("legacy_compression_methods",legacy_compression_methods);
        serverHelloInformation.put("pre_shared_key",pre_shared_key);
        serverHelloInformation.put("signature_algorithms",legacy_session_id_echo);
        serverHelloInformation.put("supported_groups",key_share);
        serverHelloInformation.put("cipher_suites",cipher_suites);
    }
    /**
     * Updates the server random value for this handshake.
     * 
     * @param information the server's random value as a hex string
     */
    public void updateServerHelloRandom (String information){
        serverHelloInformation.put("random", information);
    }

    /**
     * Updates the legacy version field of the ServerHello.
     * 
     * @param information the legacy version (typically "x0303" for TLS 1.2 compatibility)
     */
    public void updateServerHelloLegacyVersion (String information){
        serverHelloInformation.put("legacy_version", information);
    }

    /**
     * Updates the supported versions extension data.
     * 
     * @param information the supported TLS versions as a formatted string
     */
    public void updateServerHelloSupportedVersions (String information){
        serverHelloInformation.put("supported_versions",information);
    }

    /**
     * Updates the legacy compression methods field.
     * 
     * @param information the compression methods (typically "0" for TLS 1.3)
     */
    public void updateServerHelloLegacyCompressionMethods (String information){
        serverHelloInformation.put("legacy_compression_methods",information);
    }

    /**
     * Updates the pre-shared key extension data.
     * 
     * @param information the pre-shared key extension information
     */
    public void updateServerHelloPreSharedKey (String information){
        serverHelloInformation.put("pre_shared_key",information);
    }

    /**
     * Updates the legacy session ID echo field.
     * 
     * @param information the session ID echo from the client's ClientHello
     */
    public void updateServerHelloLegacySessionIdEcho (String information){
        serverHelloInformation.put("legacy_session_id_echo",information);
    }

    /**
     * Updates the key share extension data.
     * 
     * @param information the key share extension information for key exchange
     */
    public void updateServerHelloKeyShare (String information){
        serverHelloInformation.put("key_share",information);
    }

    /**
     * Updates the selected cipher suite for this connection.
     * 
     * @param information the cipher suite name selected by the server
     */
    public void updateServerHelloCipherSuites (String information){
        serverHelloInformation.put("cipher_suites",information);
    }

    /**
     * Retrieves the complete ServerHello information map.
     * 
     * @return a map containing all ServerHello message fields and their values
     */
    public Map<String, String> getServerHelloInformation(){
        return serverHelloInformation;
    }

    /**
     * Sets the complete ServerHello information from an external map.
     * This method replaces all current ServerHello information with the provided data.
     * 
     * @param info a map containing ServerHello field names and their corresponding values
     */
    public void setServerHelloInformation(Map<String, String> info){
        serverHelloInformation = info;
    }


}
