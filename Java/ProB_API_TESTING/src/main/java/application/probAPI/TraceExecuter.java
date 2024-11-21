package application.probAPI;

import com.google.inject.Inject;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;
import de.prob.statespace.Transition;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Arrays;

public class TraceExecuter {

    private final List<String> paramsSendClientHello = Arrays.asList(
            "x0303",
            "{TLS_1_3}",
            "0",
            "{}",
            "{rsa_pkcs1_sha25}",
            "{X25519}",
            "{TLS_AES_128_GCM_SHA256}"
    );
    private final List<String> paramsSendClientHelloTest = Arrays.asList(
            "x0300",
            "{TLS_1_3}",
            "0",
            "{}",
            "{rsa_pkcs1_sha25}",
            "{}",
            "{}"
    );
    private StateSpace model;
    private Trace trace;

    @Inject
    public TraceExecuter (StateSpace model){
        this.model = model;
        this.trace = new Trace(model);
    }

    // Recursive function to search for a state satisfying the predicate
    public void findStateSatisfyingPredicate(ClassicalB predicate) {
        Trace traceToSatisfyingState = model.getTraceToState(predicate);
        System.out.println("Showing State Satisfying Predicate: ");
        System.out.println(traceToSatisfyingState.forward().toString());
        System.out.println(traceToSatisfyingState);
    }
    public void createSubscription(String var) {
        ClassicalB session_machine = new ClassicalB(var);
        model.subscribe(this, session_machine);
    }

    public void generateSpecificTrace() {
        for (int i = 0; i < 2; i++){ //Set up constants + initialisation
            trace = trace.anyEvent(null);
        }
        System.out.println("Finding transitions parameters for SendClientHello: "+ trace.getCurrentState().findTransitions("SendClientHello",Arrays.asList("legacy_version=x0303","supported_versions={TLS_1_3}","legacy_compression_methods=0","pre_shared_key={}","signature_algorithms={rsa_pkcs1_sha25}"),1000));
        System.out.println("Effectuated Transitions:" + trace.getTransitionList());
        //trace = trace.anyEvent("SendClientHello");
        //System.out.println("Transition param predicates:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterPredicates());
        //System.out.println("Transition param predicate:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterPredicate());
        trace = trace.addTransitionWith("SendClientHello", paramsSendClientHello);
        System.out.println("Effectuated Transitions:" + trace.getTransitionList());
        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst());
        //trace = trace.anyEvent(null);
        trace = trace.addTransitionWith("ReceiveClientHello",Arrays.asList());
        System.out.println("Effectuated Transitions:" + trace.getTransitionList());
        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst());
        getOutTransitionInformations();
        //trace = trace.addTransitionWith("SendClientHello", paramsSendClientHelloTest);
        //trace = trace.anyEvent("ReceiveClientHello");
        //System.out.println("Readable trace information");
        //System.out.println(trace.toString());
    }
    public void generateRandomTrace (int steps){
        for (int i = 0; i < steps; i++){
            trace = trace.anyEvent(null);
        }
        System.out.println("Readable trace information");
        System.out.println(trace.toString());
    }

    public void performSpecificTransition(String operation, String[] params){
        // Check if params is null and replace it with an empty array if it is
        if (params == null) {
            params = new String[0];
        }
        trace.anyEvent(null).getCurrent().getCurrentState().perform(operation, params);
        trace.forward();
    }

    public void getOutTransitionInformations(){
        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterNames());
        System.out.println("Printing possible values for next transition:");
        for (int i = 0; i <  trace.getCurrentState().getOutTransitions().size(); i++){
            System.out.println("Transition param values:" + trace.getCurrentState().getOutTransitions().get(i).getParameterValues());

        }
    }

    public StateSpace getModel() {
        return model;
    }

    public void setModel(StateSpace model) {
        this.model = model;
    }

    public Trace getTrace() {
        return trace;
    }

    public void setTrace(Trace trace) {
        this.trace = trace;
    }
}
