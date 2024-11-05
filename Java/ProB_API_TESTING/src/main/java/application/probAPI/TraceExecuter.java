package application.probAPI;

import com.google.inject.Inject;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;
import de.prob.statespace.Transition;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class TraceExecuter {

    private StateSpace model;
    private Trace trace;

    @Inject
    public TraceExecuter (StateSpace model){
        this.model = model;
        this.trace = new Trace(model);
    }


    public void modelInformation(){
        System.out.println("--------------");
        System.out.println("Machine Constants: " + model.getLoadedMachine().getConstantNames());
        System.out.println("--------------");
        System.out.println("Machine Variables: " + model.getLoadedMachine().getVariableNames());
        System.out.println("--------------");
        System.out.println("Machine Operations: " + model.getLoadedMachine().getOperationNames());
        System.out.println("--------------");
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
        trace = trace.anyEvent("SendClientHello");
        System.out.println("Readable trace information");
        System.out.println(trace);
    }
    public void generateRandomTrace (int steps){
        for (int i = 0; i < steps; i++){
            trace = trace.anyEvent(null);
        }
        System.out.println("Readable trace information");
        System.out.println(trace);
    }

    public void performSpecificTransition(String operation, String[] params){
        trace.anyEvent(null).getCurrent().getCurrentState().perform(operation, params);
        trace.forward();
    }

    public void findTransition(){
        // Get all transitions (operations) available from the current state (which might be a Set)

        LinkedHashSet<Transition> transitionSet = (LinkedHashSet<Transition>) trace.getNextTransitions();  // This might return a Set

        // Convert the Set to a List
        List<Transition> transitions = new ArrayList<>(transitionSet);

        // Find the specific operation "increment" (or any operation you want to perform)
        Transition chosenTransition = null;
        for (Transition transition : transitions) {
            if (transition.getName().equals("VerifyClientCertificateWithCRL")) {
                chosenTransition = transition;
                break;
            } System.out.println("CurrentTransition: " + transition.getName().toString());
        }
        //System.out.println("Found transition:" + chosenTransition.getName().toString());
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
