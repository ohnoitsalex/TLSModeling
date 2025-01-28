package application.model_api;

import application.information_capture.tls_information_capture.PacketLogger;
import application.information_capture.tls_information_capture.TlsHandshakeParser;
import application.information_converter.InformationConvertertoAbstract;
import application.information_holder.tls_information_holder.TLSClientInformationHolder;
import application.information_holder.tls_information_holder.TLSServerInformationHolder;
import com.google.inject.Inject;
import de.prob.animator.domainobjects.ClassicalB;
import de.prob.statespace.StateSpace;
import de.prob.statespace.Trace;
import de.prob.statespace.Transition;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ModelExecuter {

    public static TLSClientInformationHolder tlsClientInformationHolder;
    private Map<String, String> clientHelloInformation = new HashMap<>();
    private Map<String, String> serverHelloInformation = new HashMap<>();
    public static TLSServerInformationHolder tlsServerInformationHolder;

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
        System.out.println("Possible transitions in current Trace:" + trace.getTransitionList());
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
        trace = trace.addTransitionWith("ReceiveClientHello", List.of());
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
        trace = trace.addTransitionWith("SendClientCertificateRequest", List.of());
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
        InformationConvertertoAbstract.configureYAML();

        System.out.println("Next Transition param names:" + trace.getCurrentState().getOutTransitions().getFirst().getParameterNames());
        System.out.println("Printing possible values for next transition:");
        while (trace.canGoBack()){
            trace = trace.back();
        }
        while (trace.canGoForward()) {
            trace = trace.forward();
            //System.out.println("Current State = "+trace.getCurrent().toString());
            if (trace.getCurrent().toString() == "SendClientHello"){
                System.out.println("Current Transition: SendClientHello");
                Transition transition = trace.getCurrentTransition();
                tlsClientInformationHolder = new TLSClientInformationHolder();
                //System.out.println(transition.getName().toString());
                clientHelloInformation.put("random", "NOT SUPPORTED IN MODEL ");
                clientHelloInformation.put("legacy_version", String.valueOf(transition.getParameterValues().get(0))+ " ");
                clientHelloInformation.put("supported_versions",transition.getParameterValues().get(1));
                clientHelloInformation.put("legacy_compression_methods",transition.getParameterValues().get(2));
                clientHelloInformation.put("pre_shared_key", transition.getParameterValues().get(3));
                clientHelloInformation.put("signature_algorithms", transition.getParameterValues().get(4));
                clientHelloInformation.put("supported_groups",transition.getParameterValues().get(5));
                clientHelloInformation.put("cipher_suites",transition.getParameterValues().get(6));
                tlsClientInformationHolder.setClientHelloInformation(clientHelloInformation);

                InformationConvertertoAbstract.serializeToYAML(tlsClientInformationHolder, "data/ModelClientHello");
            }
            if (trace.getCurrent().toString() == "SendServerHello"){
                System.out.println("SendServerHello");

                System.out.println("Current Transition: SendClientHello");
                Transition transition = trace.getCurrentTransition();
                tlsServerInformationHolder = new TLSServerInformationHolder();
                //System.out.println(transition.getName().toString());
                serverHelloInformation.put("random", "NOT SUPPORTED IN MODEL ");
                serverHelloInformation.put("legacy_version", transition.getParameterValues().get(0) + " ");
                serverHelloInformation.put("supported_versions",transition.getParameterValues().get(3));
                serverHelloInformation.put("legacy_compression_methods",(transition.getParameterValues().get(2)));
                serverHelloInformation.put("pre_shared_key", transition.getParameterValues().get(6));
                serverHelloInformation.put("legacy_session_id_echo", String.valueOf(transition.getParameterValues().get(1)) + " ");
                serverHelloInformation.put("key_share",transition.getParameterValues().get(5));
                serverHelloInformation.put("cipher_suites",String.valueOf(transition.getParameterValues().get(4)) + " ");
                tlsServerInformationHolder.setServerHelloInformation(serverHelloInformation);

                //InformationConvertertoAbstract.configureYAML();
                InformationConvertertoAbstract.serializeToYAML(tlsServerInformationHolder, "data/ModelServerHello");
            }

            //System.out.println("Transition param values:" + trace.getCurrentState().getOutTransitions().toString());

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
