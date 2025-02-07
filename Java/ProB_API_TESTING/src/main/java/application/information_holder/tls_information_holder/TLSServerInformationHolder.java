package application.information_holder.tls_information_holder;

import application.information_handler.InformationConvertertoAbstract;

import java.util.HashMap;
import java.util.Map;

public class TLSServerInformationHolder {

    public static void main(String[] args) {
        TLSClientInformationHolder test = new TLSClientInformationHolder();
        test.updateClientHelloInformation("test","test","test","test","test","test","test", "test");
        InformationConvertertoAbstract.configureYAML();
        InformationConvertertoAbstract.serializeToYAML(test, "");
    }

    // Create a HashMap
    private static Map<String, String> serverHelloInformation = new HashMap<>();

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
    public void updateServerHelloRandom (String information){
        serverHelloInformation.put("random", information);
    }

    public void updateServerHelloLegacyVersion (String information){
        serverHelloInformation.put("legacy_version", information);
    }

    public void updateServerHelloSupportedVersions (String information){
        serverHelloInformation.put("supported_versions",information);
    }

    public void updateServerHelloLegacyCompressionMethods (String information){
        serverHelloInformation.put("legacy_compression_methods",information);
    }

    public void updateServerHelloPreSharedKey (String information){
        serverHelloInformation.put("pre_shared_key",information);
    }

    public void updateServerHelloLegacySessionIdEcho (String information){
        serverHelloInformation.put("legacy_session_id_echo",information);
    }

    public void updateServerHelloKeyShare (String information){
        serverHelloInformation.put("key_share",information);
    }

    public void updateServerHelloCipherSuites (String information){
        serverHelloInformation.put("cipher_suites",information);
    }

    public Map<String, String> getServerHelloInformation(){
        return this.serverHelloInformation;
    }

    public void setServerHelloInformation(Map<String, String> info){
        this.serverHelloInformation = info;
    }


}
