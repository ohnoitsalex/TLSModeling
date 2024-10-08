package application.probAPI;

import com.google.inject.Inject;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;

public class TraceExecuter {

    private StateSpace model;
    private Trace trace;

    @Inject
    public TraceExecuter (StateSpace model){
        this.model = model;
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

    public void generateRandomTrace (int steps){
        Trace trace = new Trace(model);
        for (int i = 0; i < steps; i++){
            trace = trace.anyEvent(null);
        }
        System.out.println("Readable trace information");
        System.out.println(trace);
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
