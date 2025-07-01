package application.test_examiner;

import application.config.Config;
import application.information_handler.AbstractInformationComparator;
import application.information_handler.InformationConvertertoAbstract;
import application.model_api.ModelExecuter;
import application.model_api.ModelLoader;
import application.system_under_test.SystemUnderTest;
import application.system_under_test.tls_attacker.TLSAttackerFakeClient;
import application.system_under_test.tls_attacker.TLSAttackerSUTServer;
import application.system_under_test.tls_attacker.utils.TlsYamlParser;
import application.system_under_test.tls_system_under_test.TLSSystemUnderTest;

import java.util.Map;

import com.google.inject.Guice;
import com.google.inject.Injector;
import de.prob.MainModule;
import de.prob.scripting.Api;

public class TestExaminer {

    /* Type of the test examiner */
    private ModelLoader modelLoader;

    /* System Under Test (SUT) */
    private SystemUnderTest systemUnderTest;
    private SystemUnderTest fakeClient;

    /* Client or server SUT */
    private String mode;

    public TestExaminer(String type) {

        // Initialize Guice injector to load the ProB API
        Injector injector = Guice.createInjector(new MainModule());
        Api api = injector.getInstance(Api.class);

        switch (type) {
            case "tls":
                this.modelLoader = new ModelLoader(
                    api,
                    Config.TLSMODELFILEPATH
                );

                this.systemUnderTest = new TLSAttackerSUTServer();
                this.fakeClient = new TLSAttackerFakeClient();

                break;
            //Simply to show the flexibility and adaptation of the code
            case "tlsTesting":
                this.modelLoader = new ModelLoader(
                    api,
                    Config.TLSMODELFORTESTINGFILEPATH
                );
                //this.systemUnderTest = new SystemUnderTest();
                break;
            default:
                System.out.println("Invalid Test Examiner Type");
        }
    }

    public void runTest() {
        System.out.println("-- Starting TLS Test --");

        // Load model
        loadModel();

        //Generate ClientHello
        System.out.println("Generating and testing ClientHello");
        modelLoader.generateClientHello();


        // Launch real SUT (System Under Test)
        if (systemUnderTest != null) {
            System.out.println("Starting SUT ...");
            systemUnderTest.createSUT();
            systemUnderTest.startSUT();
        }

        // Create and execute the fake client with tls attacker as a client
        if (fakeClient != null) {
            System.out.println("Starting client with tls attacker...");
            fakeClient.createSUT();
        }

        // Results comparison
        // compareResults();

        boolean isValid = modelLoader.validateServerHelloFromSUT("src/main/resources/data/SUTServerHello.yaml");

        if (isValid) {
            System.out.println("ServerHello is valid according to the model.");
        } else {
            System.out.println("ServerHello is invalid according to the model.");
        }

        
    }

    public void loadModel() {
        System.out.println("Testing TLS Model...");
        this.modelLoader.loadAndExecuteAPI();
        this.modelLoader.modelInformation();
    }

    // public void createSUT() {
    //     systemUnderTest.startSUT();
    // }

    public void createSUTForServerHello() {}

    public void executeSUTOperation() {}

    //    KEEPING FOR FURTHER IMPLEMENTATIONS
    //    public void executeModelOperation() {
    //        this.modelLoader.executeSpecificTrace();
    //    }

    public void testServerHello() {
        this.modelLoader.generateClientAndServerHello();
    }

    public void compareResults() {
        System.out.println("Comparing YAML result");
        boolean match;

        switch (mode) {
            case "client":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/SUTServerHello.yaml"
                    ),
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/ModelServerHello.yaml"
                    ),
                    ""
                );
                break;
            case "server":
                match = AbstractInformationComparator.compareAbstractYaml(
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/SUTClientHello.yaml"
                    ),
                    InformationConvertertoAbstract.retreiveYamlInformation(
                        "src/main/resources/data/ModelClientHello.yaml"
                    ),
                    ""
                );
                break;
            default:
                throw new IllegalArgumentException("Unknown SUT mode: " + mode);
        }

        System.out.println(match ? "Match found!" : "No match found!");
    }


    



}
