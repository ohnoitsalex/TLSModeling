package application.test_examiner;

import application.config.Config;
import application.information_handler.AbstractInformationComparator;
import application.information_handler.InformationConvertertoAbstract;
import application.model_api.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.TLSAttackerClientRunner;
import application.system_under_test.tls_attacker.TLSAttackerServerRunner;
import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;
import de.prob.scripting.Api;

import com.google.inject.Guice;
import com.google.inject.Injector;
import de.prob.MainModule;



public class TestExaminer {

    /* Type of the test examiner */
    private ModelLoader modelLoader;

    /* System Under Test (SUT) */
    private SystemUnderTest systemUnderTest;
    private SystemUnderTest oppositeTester;

    /* Client or server SUT */
    private String mode; 

    public TestExaminer(String type, String mode) {
        this.mode = mode;

        // Initialize Guice injector to load the ProB API
        Injector injector = Guice.createInjector(new MainModule());
        Api api = injector.getInstance(Api.class);


        switch (type) {
            case "tls":
                this.modelLoader = new ModelLoader(api, Config.TLSMODELFILEPATH);

                if ("client".equalsIgnoreCase(mode)) {
                    this.systemUnderTest = new TLSSystemUnderTest("client");
                    this.oppositeTester = new TLSAttackerServerRunner();
                } else if ("server".equalsIgnoreCase(mode)) {
                    this.systemUnderTest = new TLSSystemUnderTest("server");
                    this.oppositeTester = new TLSAttackerClientRunner();
                } else {
                    throw new IllegalArgumentException("Unknown SUT mode: " + mode);
                }
                // this.systemUnderTest = new TLSSystemUnderTest();
                break;

            //Simply to show the flexibility and adaptation of the code
            case "tlsTesting":
                this.modelLoader = new ModelLoader(api, Config.TLSMODELFORTESTINGFILEPATH);
                //this.systemUnderTest = new SystemUnderTest();
                break;
            default:
                System.out.println("Invalid Test Examiner Type");
        }
    }

    public void runTest(){
        System.out.println("Stargin TLS Test (mode: " + mode + ")");

        // Load model
        loadModel();

        // Launch real SUT (System Under Test)
        if (systemUnderTest != null) {
            systemUnderTest.startSUT();
        }

        // Create and execute SUT (client or server)
        if (oppositeTester != null){
            oppositeTester.createSUT();
            if ("server".equalsIgnoreCase(mode)){
                oppositeTester.startSUT();
                oppositeTester.executeSUTOperation();
            }
        }

        // Results comparison
        compareResults();
    }

    public void loadModel() {
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }

    public void createSUT() {
        systemUnderTest.startSUT();
    }
    public void createSUTForServerHello(){

    }

    public void executeSUTOperation() {

    }

//    KEEPING FOR FURTHER IMPLEMENTATIONS
//    public void executeModelOperation() {
//        this.modelLoader.executeSpecificTrace();
//    }

    public void testServerHello(){
        this.modelLoader.generateClientAndServerHello();
    }

    public void compareResults() {
        System.out.println("Comparing YAML resultas");
        boolean match;

        switch (mode){
            case "client":
                match = AbstractInformationComparator.compareAbstractYaml( InformationConvertertoAbstract.retreiveYamlInformation("src/main/ressources/data/SUTServerHello.yaml"), InformationConvertertoAbstract.retreiveYamlInformation("src/main/ressources/data/ModelServerHello.yaml"), "");
                break;
            case "server":
                match = AbstractInformationComparator.compareAbstractYaml( InformationConvertertoAbstract.retreiveYamlInformation("src/main/ressources/data/SUTClientHello.yaml"), InformationConvertertoAbstract.retreiveYamlInformation("src/main/ressources/data/ModelClientHello.yaml"), "");
                break;
            default:
                throw new IllegalArgumentException("Unknown SUT mode: " + mode);
        }

        System.out.println(match ? "Match found!" : "No match found!");

    }
}
