package application.probAPI;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Stage;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.scripting.Api;
import de.prob.statespace.StateSpace;
import application.config.Config;

import java.nio.file.Paths;

public class Loader {

    /**
     * Injector class -> Installs and injects ProB 2.0 Bindings
     */
    private static final Injector INJECTOR = Guice.createInjector(Stage.PRODUCTION, new Config());

    private Api api;
    private StateSpace model;
    private TraceExecuter traceExecuter;

    @Inject
    public Loader(Api api){
        this.api = api;
    }
    public void loadAndExecuteAPI(String proBModelPath){
        try {
            System.out.println("LOADING B MACHINE (.mch file)");
            model = api.load(Paths.get(proBModelPath).toAbsolutePath().toString());
            model.execute();
            model.performExtendedStaticChecks();
            traceExecuter = new TraceExecuter(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void modelInformation(){
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

    public void executeRandomTrace(int steps){
        traceExecuter.createSubscription("session_machine");
        traceExecuter.generateRandomTrace(10);
    }

    public void executeSpecificTrace(){
        traceExecuter.createSubscription("session_machine");
        traceExecuter.generateSpecificTrace();
    }
}
