package application.probAPI;

import com.google.inject.Inject;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;

import java.util.Arrays;
import java.util.List;

public class ModelExecuter {

    private final List<String> paramsSendClientHello = Arrays.asList(
            "x0303",
            "{TLS_1_3}",
            "0",
            "{}",
            "{rsa_pkcs1_sha25}",
            "{X25519}",
            "{TLS_AES_128_GCM_SHA256}"
    );

    private final List<String> paramsFindSendClientHello = Arrays.asList(
            "legacy_version=x0303",
            "supported_versions={TLS_1_3}",
            "legacy_compression_methods=0",
            "pre_shared_key={}",
            "signature_algorithms={rsa_pkcs1_sha25}",
            "supported_groups={X25519}",
            "cipher_suites={TLS_AES_128_GCM_SHA256}"
    );

    private final List<String> paramsFindSendServerHello = Arrays.asList(
            "legacy_version=x0303",
            "legacy_session_id_echo=x0303",
            "legacy_compression_methods=0",
            "supported_versions={TLS_1_3}",
            "cipher_suites=TLS_AES_128_GCM_SHA256",
            "key_share={}",
            "pre_shared_key={}",
            "random=A1"
    );

    private final List<String> paramsSendServerHello = Arrays.asList(
            "x0303",
            "x0303",
            "0",
            "{TLS_1_3}",
            "TLS_AES_128_GCM_SHA256",
            "{}",
            "{}",
            "A1"
    );

    private final List<String> paramsSendEncryptedExtensions = Arrays.asList(
            "rsa_pkcs1_sha25",
            "X25519"
    );

    private final List<String> paramsFindSendServerCertificate = Arrays.asList(
            "raw_public_key_certificate=A1B1C1",
            "certificate_type=X509",
            "signed_certificate_timestamp=D20241231",
            "ocsp_status=1",
            "certificate_authorities=ENTRUST",
            "server_certificate_request_context=C1",
            "serial_number=0"
    );

    private final List<String> paramsSendServerCertificate = Arrays.asList(
            "A1B1C1",
            "X509",
            "D20241231",
            "1",
            "ENTRUST",
            "C1",
            "0"
    );
    private StateSpace model;
    private Trace trace;

    @Inject
    public ModelExecuter(StateSpace model) {
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
        initaliseMachine();
        generateClientHelloMessages();
        generateServerHelloMessages();
        //generateServerHelloMessagesWithoutClientCertificateRequest();
        getOutTransitionInformations();
        System.out.println("Effectuated Transitions:" + trace.getTransitionList());
    }

    public void generateRandomTrace(int steps) {
        for (int i = 0; i < steps; i++) {
            trace = trace.anyEvent(null);
        }
        System.out.println("Readable trace information");
        System.out.println(trace.toString());
    }

    public void initaliseMachine() {
        for (int i = 0; i < 2; i++) { //Set up constants + initialisation
            trace = trace.anyEvent(null);
        }
        System.out.println("Effectuated Transitions:" + trace.getTransitionList());
    }

    public void generateClientHelloMessages() {
        trace.getCurrentState().findTransitions("SendClientHello", paramsFindSendClientHello, 1000);
        trace = trace.addTransitionWith("SendClientHello", paramsSendClientHello);
        trace = trace.addTransitionWith("ReceiveClientHello", Arrays.asList());
    }

    public void generateServerHelloMessages() {
        trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1000);
        trace = trace.addTransitionWith("SendServerHello", paramsSendServerHello);
        trace = trace.addTransitionWith("SendEncryptedExtensions", paramsSendEncryptedExtensions);
        trace.getCurrentState().findTransitions("SendServerCertificate", paramsFindSendServerCertificate, 1000);
        trace = trace.addTransitionWith("SendServerCertificate", paramsSendServerCertificate);
    }

    public void generateServerHelloMessagesWithoutClientCertificateRequest() {
        trace.getCurrentState().findTransitions("SendServerHello", paramsFindSendServerHello, 1000);
        trace = trace.addTransitionWith("SendServerHello", paramsSendServerHello);
        trace = trace.addTransitionWith("SendEncryptedExtensions", paramsSendEncryptedExtensions);
        trace = trace.addTransitionWith("SendClientCertificateRequest", Arrays.asList());
    }

    public void performSpecificTransition(String operation, String[] params) {
        // Check if params is null and replace it with an empty array if it is
        if (params == null) {
            params = new String[0];
        }
        trace.anyEvent(null).getCurrent().getCurrentState().perform(operation, params);
        trace.forward();
    }

    public void getOutTransitionInformations() {
        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterNames());
        System.out.println("Printing possible values for next transition:");
        for (int i = 0; i < trace.getCurrentState().getOutTransitions().size(); i++) {
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
