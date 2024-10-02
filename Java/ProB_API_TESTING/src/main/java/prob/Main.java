package prob;

import prob.api.Loader;

public class Main {


    public static void main(String[] args) {
        testingLibaryExample();

    }
    public static void testingLibaryExample(){
        System.out.println("Testing...");
        Loader loader = new Loader();
        loader.loadAndExecuteAPI("/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch");
        loader.printMachineInformation();
    }
}