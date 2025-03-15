package application.system_under_test.tls_system_under_test.bouncy_castle.tls_attacker;


import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;

public class TestingClientTlsAttacker {

    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 1234;

    public static void main(String[] args) {

        Config config = Config.createConfig();

        // Set target host and port
        config.setDefaultRunningMode(RunningModeType.CLIENT);
        config.setWorkflowExecutorShouldClose(true);
        config.setDefaultClientConnection(new OutboundConnection(SERVER_PORT, SERVER_HOST));

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(new SendAction(new ClientHelloMessage()));
        trace.addTlsAction(new ReceiveAction(new ServerHelloMessage()));
        State state = new State(config, trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
//
//
//        // Set up configuration
//        Config config = Config.createConfig();
//
//        // Create a custom ClientHello message
//        ClientHelloMessage clientHello = new ClientHelloMessage(config);
//
//        // Add SupportedVersions extension (e.g., TLS 1.3)
//        SupportedVersionsExtensionMessage supportedVersions = new SupportedVersionsExtensionMessage();
//        supportedVersions.setSupportedVersions(new byte[]{0x03, 0x04}); // TLS 1.3
//        clientHello.addExtension(supportedVersions);
//
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
//
//        // Print result
//        System.out.println("ClientHello sent to the server.");
    }
}
