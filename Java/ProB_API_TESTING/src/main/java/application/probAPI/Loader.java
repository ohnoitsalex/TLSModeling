package application.probAPI;

import com.google.inject.Guice;
import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Stage;
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
            model = api.load(proBModelPath);
            model.execute();
            model.performExtendedStaticChecks();
            traceExecuter = new TraceExecuter(model);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void executeOperation() {
        String[] paramsSendClientHello = {"legacy_version=x0303","supported_versions={TLS_1_3}","legacy_compression_methods=0","pre_shared_key={}", "signature_algorithms={rsa_pkcs1_sha25}",
        "supported_groups={X25519}", "cipher_suites={TLS_AES_128_GCM_SHA256}"};
        String[] paramsReceiveClientHello = {};
        traceExecuter.createSubscription("session_machine");
        //traceExecuter.generateRandomTrace(10);
        //traceExecuter.findStateSatisfyingPredicate(new ClassicalB("session_machine'State == RECEIVECLIENTHELLO"));
        //traceExecuter.generateRandomTrace(4);
        traceExecuter.generateSpecificTrace();
        //traceExecuter.performSpecificTransition("SendClientHello", paramsSendClientHello);
        //traceExecuter.performSpecificTransition("ReceiveClientHello",null);
        //traceExecuter.performSpecificTransition("ReceiveClientHello", paramsReceiveClientHello);
        //traceExecuter.findTransition();

    }
}
