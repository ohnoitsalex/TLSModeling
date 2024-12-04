package application.test_examiner;

import application.config.Config;
import application.model_api.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;
import de.prob.scripting.Api;

public class TestExaminer {
    private ModelLoader modelLoader;
    private SystemUnderTest systemUnderTest;

    public TestExaminer(String type){

        switch (type){
            case "tls":
                this.modelLoader = new ModelLoader(de.prob.Main.getInjector().getInstance(Api.class), Config.TLSMODELFILEPATH);
                this.systemUnderTest = new TLSSystemUnderTest();
                break;

            //Simply to show the flexibility and adaptation of the code
            case "libraryExample":
                this.modelLoader = new ModelLoader(de.prob.Main.getInjector().getInstance(Api.class), Config.LIBRARYMODELFILEPATH);
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
