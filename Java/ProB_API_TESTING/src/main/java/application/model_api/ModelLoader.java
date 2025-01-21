package application.model_api;

import application.config.Config;
import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Stage;
import de.prob.scripting.Api;
import de.prob.statespace.StateSpace;

import java.nio.file.Paths;

public class ModelLoader {

    /**
     * Injector class -> Installs and injects ProB 2.0 Bindings
     */
    private static final Injector INJECTOR = Guice.createInjector(Stage.PRODUCTION, new Config());

    private final String modelFilePath;

    private final Api api;
    private StateSpace model;
    private ModelExecuter modelExecuter;

    @Inject
    public ModelLoader(Api api, String modelFilePath) {

        this.api = api;

        this.modelFilePath = modelFilePath;
    }

    public void loadAndExecuteAPI() {
        try {
            System.out.println("LOADING B MACHINE (.mch file)");
            model = api.load(Paths.get(this.modelFilePath).toAbsolutePath().toString());
            model.execute();
            model.performExtendedStaticChecks();
            modelExecuter = new ModelExecuter(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void modelInformation() {
        System.out.println("--------------");
        System.out.println("Machine Set Names: " + model.getLoadedMachine().getSetNames());
        System.out.println("--------------");
        System.out.println("Machine Constant Names: " + model.getLoadedMachine().getConstantNames());
        System.out.println("--------------");
        System.out.println("Machine Variable Names: " + model.getLoadedMachine().getVariableNames());
        System.out.println("--------------");
        System.out.println("Machine Operations Names: " + model.getLoadedMachine().getOperationNames());
        System.out.println("--------------");
    }

    public void executeRandomTrace(int steps) {
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateRandomTrace(10);
    }

    public void executeSpecificTrace() {
        modelExecuter.createSubscription("session_machine");
        modelExecuter.generateSpecificTrace();
    }
}
