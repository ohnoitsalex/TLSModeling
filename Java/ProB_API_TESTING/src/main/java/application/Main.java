package application;

import de.prob.scripting.Api;
import application.probAPI.Loader;

public class Main {
    private static final String libraryFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch";
    private static final String tlsModelFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/TLS_specification.mch";
    public static void main(String[] args) {
        loadTLSModel();
    }

    public static void loadTLSModel(){
        System.out.println("Testing TLS Model...");
        Loader loader = new Loader(de.prob.Main.getInjector().getInstance(Api.class));
        loader.loadAndExecuteAPI(tlsModelFilePath);
        loader.modelInformation();
        loader.executeSpecificTrace();
    }
    public static void loadLibaryExample(){
        System.out.println("Testing Library Model...");
        Loader loader = new Loader(de.prob.Main.getInjector().getInstance(Api.class));
        loader.loadAndExecuteAPI(libraryFilePath);
        loader.modelInformation();
        loader.executeSpecificTrace();
    }
}