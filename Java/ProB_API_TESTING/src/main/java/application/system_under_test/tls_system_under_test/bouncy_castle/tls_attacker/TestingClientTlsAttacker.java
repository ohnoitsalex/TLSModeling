package application.system_under_test.tls_system_under_test.bouncy_castle.tls_attacker;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

import java.util.Arrays;
import java.util.List;
import java.util.Vector;

public class TestingClientTlsAttacker {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;

    private static final byte[] signature_algorithms = new byte[]{0x04, 0x01, 0x05, 0x01};
    private static final Vector <SignatureAndHashAlgorithm> signature_algorithms_cert = new Vector<>();
    private static final byte[] key_share = new byte[]{0x00, 0x1D, 0x00, 0x20};
    private static final byte[] tls_versions = new byte[]{0x03, 0x04};
    private static final List<CipherSuite> enabled_cipher_suites = Arrays.asList(
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256
    );


    public static void main(String[] args) {

        // Set up connexion config
        Config config = Config.createConfig();

        // Adding Cipher Suites Extension
        config.setDefaultClientSupportedCipherSuites(enabled_cipher_suites);

        // Adding Supported Groups Extension
        config.setDefaultClientNamedGroups(Arrays.asList(
                NamedGroup.ECDH_X448
        ));

        // Set target host and port
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        config.setWorkflowExecutorShouldClose(true);
        config.setDefaultClientConnection(new OutboundConnection(SERVER_PORT, SERVER_HOST));

        // ==== Create a custom ClientHello message ====
        ClientHelloMessage clientHello = new ClientHelloMessage(config);

        // Add SupportedVersions extension
        SupportedVersionsExtensionMessage supportedVersions = new SupportedVersionsExtensionMessage();
        supportedVersions.setSupportedVersions(tls_versions);
        clientHello.addExtension(supportedVersions);

        // Signature and Hash Algorithms
        SignatureAndHashAlgorithmsExtensionMessage sigHash = new SignatureAndHashAlgorithmsExtensionMessage();
        sigHash.setSignatureAndHashAlgorithms(signature_algorithms);
        clientHello.addExtension(sigHash);

        // Key Share
        KeyShareExtensionMessage keyShare = new KeyShareExtensionMessage();
        keyShare.setKeyShareListBytes(key_share);
        clientHello.addExtension(keyShare);


        // Adding ClientHello to WorkflowTrace
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));

        // Receive ServerHello message
        ServerHelloMessage serverHello = new ServerHelloMessage();
        trace.addTlsAction(new ReceiveAction(serverHello));

        // Execution of the Workflow
        State state = new State(config, trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();

        // Print result
        System.out.println("ClientHello sent to the server.");
        System.out.println("ServerHello received :");
        System.out.println(serverHello.toString());

//
//        // Set up configuration
//        Config config = Config.createConfig();
//
//        // Create a custom ClientHello message
//        ClientHelloMessage clientHello = new ClientHelloMessage(config);
///

//        // Create a workflow trace using the factory
//        WorkflowTrace trace = WorkflowTraceFactory.createWorkflowTrace(WorkflowTraceType.HELLO, config);
//
//        // Manually add ClientHello inside a SendAction
//        trace.addTlsAction(new SendAction(clientHello));
//        trace.addTlsAction(new ReceiveAction());
//        // Create a state with the custom ClientHello
//        State state = new State(config);
//        state.getWorkflowTrace().addTlsAction(clientHello);
//
//        // Execute the handshake workflow
//        WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
//        executor.executeWorkflow();

    }
}
