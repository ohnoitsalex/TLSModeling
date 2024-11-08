package application;

import de.prob.scripting.Api;
import application.probAPI.Loader;

public class Main {
    private static final String libraryFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch";
    private static final String tlsFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/TLS_specificationTesting.mch";
    public static void main(String[] args) {
        loadLibaryExample();
    }
    public static void loadLibaryExample(){
        System.out.println("Testing...");
        Loader loader = new Loader(de.prob.Main.getInjector().getInstance(Api.class));
        //loader.loadAndExecuteAPI(libraryFilePath);
        loader.loadAndExecuteAPI(tlsFilePath);
        //loader.printMachineInformation();
        loader.executeOperation();
    }
}