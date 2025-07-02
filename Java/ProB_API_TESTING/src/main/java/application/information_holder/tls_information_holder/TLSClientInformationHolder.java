package application.information_holder.tls_information_holder;

import application.information_handler.InformationConvertertoAbstract;
import application.information_holder.InformationHolder;

import java.util.HashMap;
import java.util.Map;

/**
 * Information holder for TLS ClientHello message data.
 * This class stores and manages all relevant information extracted from ClientHello messages
 * during TLS handshake testing, providing standardized access to client-side handshake parameters.
 * 
 * <p>The stored information includes:
 * <ul>
 *   <li>Client random value</li>
 *   <li>Protocol version information (legacy and supported versions)</li>
 *   <li>Cipher suites and compression methods</li>
 *   <li>Extension data (signature algorithms, supported groups, pre-shared keys)</li>
 * </ul>
 * 
 */
public class TLSClientInformationHolder extends InformationHolder {

    // Create a HashMap
    private Map<String, String> clientHelloInformation = new HashMap<>();

    /**
     * Default constructor that initializes all ClientHello fields to null.
     * Creates a HashMap with standard TLS ClientHello message fields ready for population.
     */
    public TLSClientInformationHolder(){
        clientHelloInformation.put("random", null);
        clientHelloInformation.put("legacy_version", null);
        clientHelloInformation.put("supported_versions",null);
        clientHelloInformation.put("legacy_compression_methods",null);
        clientHelloInformation.put("pre_shared_key",null);
        clientHelloInformation.put("signature_algorithms",null);
        clientHelloInformation.put("supported_groups",null);
        clientHelloInformation.put("cipher_suites",null);
    }

    /**
     * Updates all ClientHello information fields in a single operation.
     * This method provides a convenient way to populate all ClientHello fields at once.
     * 
     * @param random the client's random value for this handshake
     * @param legacy_version the legacy version field (typically 0x0303 for TLS 1.2)
     * @param supported_versions the list of supported TLS versions
     * @param legacy_compression_methods the compression methods offered by the client
     * @param pre_shared_key pre-shared key extension data
     * @param signature_algorithms the supported signature algorithms
     * @param supported_groups the supported named groups for key exchange
     * @param cipher_suites the list of cipher suites offered by the client
     */
    public void updateClientHelloInformation(String random, String legacy_version, String supported_versions, String legacy_compression_methods,
                                             String pre_shared_key, String signature_algorithms, String supported_groups,
                                             String cipher_suites){
        clientHelloInformation.put("random", random);
        clientHelloInformation.put("legacy_version", legacy_version);
        clientHelloInformation.put("supported_versions",supported_versions);
        clientHelloInformation.put("legacy_compression_methods",legacy_compression_methods);
        clientHelloInformation.put("pre_shared_key",pre_shared_key);
        clientHelloInformation.put("signature_algorithms",signature_algorithms);
        clientHelloInformation.put("supported_groups",supported_groups);
        clientHelloInformation.put("cipher_suites",cipher_suites);
    }
    /**
     * Updates the client random value for this handshake.
     * 
     * @param information the client's random value as a hex string
     */
    public void updateClientHelloRandom (String information){
        clientHelloInformation.put("random", information);
    }

    /**
     * Updates the legacy version field of the ClientHello.
     * 
     * @param information the legacy version (typically "x0303" for TLS 1.2 compatibility)
     */
    public void updateClientHelloLegacyVersion (String information){
        clientHelloInformation.put("legacy_version", information);
    }

    /**
     * Updates the supported versions extension data.
     * 
     * @param information the supported TLS versions as a formatted string
     */
    public void updateClientHelloSupportedVersions (String information){
        clientHelloInformation.put("supported_versions",information);
    }

    /**
     * Updates the legacy compression methods field.
     * 
     * @param information the compression methods offered by the client
     */
    public void updateClientHelloLegacyCompressionMethods (String information){
        clientHelloInformation.put("legacy_compression_methods",information);
    }

    /**
     * Updates the pre-shared key extension data.
     * 
     * @param information the pre-shared key extension information
     */
    public void updateClientHelloPreSharedKey (String information){
        clientHelloInformation.put("pre_shared_key",information);
    }

    /**
     * Updates the signature algorithms extension data.
     * 
     * @param information the supported signature algorithms
     */
    public void updateClientHelloSignatureAlgorithm (String information){
        clientHelloInformation.put("signature_algorithms",information);
    }

    /**
     * Updates the supported groups extension data.
     * 
     * @param information the supported named groups for key exchange
     */
    public void updateClientHelloSupportedGroups (String information){
        clientHelloInformation.put("supported_groups",information);
    }

    /**
     * Updates the cipher suites offered by the client.
     * 
     * @param information the list of cipher suites supported by the client
     */
    public void updateClientHelloCipherSuites (String information){
        clientHelloInformation.put("cipher_suites",information);
    }

    /**
     * Retrieves the complete ClientHello information map.
     * 
     * @return a map containing all ClientHello message fields and their values
     */
    public Map<String, String> getClientHelloInformation(){
        return this.clientHelloInformation;
    }

    /**
     * Sets the complete ClientHello information from an external map.
     * This method replaces all current ClientHello information with the provided data.
     * 
     * @param info a map containing ClientHello field names and their corresponding values
     */
    public void setClientHelloInformation(Map<String, String> info){
         this.clientHelloInformation = info;
    }

}