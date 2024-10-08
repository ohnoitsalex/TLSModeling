package application.probAPI;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Stage;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.scripting.Api;
import de.prob.statespace.StateSpace;
import application.config.Config;

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
            model = api.b_load(proBModelPath);
            model.execute();
            model.performExtendedStaticChecks();
            traceExecuter = new TraceExecuter(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void executeOperation() {

        traceExecuter.createSubscription("session_machine");
        //traceExecuter.generateRandomTrace(10);
        traceExecuter.findStateSatisfyingPredicate(new ClassicalB("session_machine'State = RECEIVECLIENTHELLO"));

    }
}
