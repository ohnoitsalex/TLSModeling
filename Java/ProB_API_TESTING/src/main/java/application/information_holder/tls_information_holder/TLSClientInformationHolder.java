package application.information_holder.tls_information_holder;

import application.information_converter.InformationConvertertoAbstract;
import application.information_holder.InformationHolder;

import java.util.HashMap;
import java.util.Map;

public class TLSClientInformationHolder extends InformationHolder {

    public static void main(String[] args) {
        TLSClientInformationHolder test = new TLSClientInformationHolder();
        test.updateClientHelloInformation("test","test","test","test","test","test","test", "test");
        InformationConvertertoAbstract.configureYAML();
        InformationConvertertoAbstract.serializeToYAML(test, "ClientHello");
    }

    // Create a HashMap
    private Map<String, String> clientHelloInformation = new HashMap<>();

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
    public void updateClientHelloRandom (String information){
        clientHelloInformation.put("random", information);
    }

    public void updateClientHelloLegacyVersion (String information){
        clientHelloInformation.put("legacy_version", information);
    }

    public void updateClientHelloSupportedVersions (String information){
        clientHelloInformation.put("supported_versions",information);
    }

    public void updateClientHelloLegacyCompressionMethods (String information){
        clientHelloInformation.put("legacy_compression_methods",information);
    }

    public void updateClientHelloPreSharedKey (String information){
        clientHelloInformation.put("pre_shared_key",information);
    }

    public void updateClientHelloSignatureAlgorithm (String information){
        clientHelloInformation.put("signature_algorithms",information);
    }

    public void updateClientHelloSupportedGroups (String information){
        clientHelloInformation.put("supported_groups",information);
    }

    public void updateClientHelloCipherSuites (String information){
        clientHelloInformation.put("cipher_suites",information);
    }

    public Map<String, String> getClientHelloInformation(){
        return this.clientHelloInformation;
    }

    public void setClientHelloInformation(Map<String, String> info){
         this.clientHelloInformation = info;
    }


}