package application;

import application.packet_capture.PacketSniffer;
import application.system_under_test.Client;
import application.system_under_test.Server;
import de.prob.scripting.Api;
import application.probAPI.Loader;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

public class Main {
    private static final String libraryFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch";
    private static final String tlsFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/TLS_specificationTesting.mch";
    public static void main(String[] args) throws NotOpenException, PcapNativeException {

        loadLibaryExample();

        //testPacketSniffer();
    }
    public static void loadLibaryExample(){
        System.out.println("Testing...");
        Loader loader = new Loader(de.prob.Main.getInjector().getInstance(Api.class));
        //loader.loadAndExecuteAPI(libraryFilePath);
        loader.loadAndExecuteAPI(tlsFilePath);
        //loader.printMachineInformation();
        loader.executeOperation();
    }

    public static void testPacketSniffer() throws NotOpenException, PcapNativeException {
        Server.main(null);
        Client.main(null);
        PacketSniffer.main(null);
    }
}