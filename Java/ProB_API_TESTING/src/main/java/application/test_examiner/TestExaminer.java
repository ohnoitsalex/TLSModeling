package application.test_examiner;

import application.probAPI.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;
import de.prob.scripting.Api;

public class TestExaminer {

    private static final String tlsModelFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/TLS_specification.mch";
    private static final String libraryFilePath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/src/main/resources/models/Library_Example.mch";
    private ModelLoader modelLoader;
    private SystemUnderTest systemUnderTest;

    public TestExaminer(String type){

        switch (type){
            case "tls":
                this.modelLoader = new ModelLoader(de.prob.Main.getInjector().getInstance(Api.class), tlsModelFilePath);
                this.systemUnderTest = new TLSSystemUnderTest();
                break;

            //Simply to show the flexibility and adaptation of the code
            case "libraryExample":
                this.modelLoader = new ModelLoader(de.prob.Main.getInjector().getInstance(Api.class), libraryFilePath);
                //this.systemUnderTest = new SystemUnderTest();
                break;
            default:
                System.out.println("Invalid Test Examiner Type");
        }
    }

    public void loadModel(){
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }


    public void createSUT(){
        systemUnderTest.startSUT();
    }

    public void executeSUTOperation(){

    }

    public void executeModelOperation(){
        this.modelLoader.executeSpecificTrace();
    }

    public void compareResults(){

    }
}
