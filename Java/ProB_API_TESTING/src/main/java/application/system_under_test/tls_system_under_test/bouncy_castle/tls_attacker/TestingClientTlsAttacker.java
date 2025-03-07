package application.system_under_test.tls_system_under_test.bouncy_castle.tls_attacker;


public class TestingClientTlsAttacker {

    public static void main(String[] args) {
        // Set up configuration
        //Config config = Config.createConfig();

//        // Create a custom ClientHello message
//        ClientHelloMessage clientHello = new ClientHelloMessage(config);
//
//        // Optionally modify ClientHello properties (e.g., specific TLS version, extensions)
//        clientHello.getProtocolVersion().setValue(new byte[]{0x03, 0x03}); // TLS 1.2
//
//        // Add SupportedVersions extension (e.g., TLS 1.3)
//        SupportedVersionsExtensionMessage supportedVersions = new SupportedVersionsExtensionMessage();
//        supportedVersions.setSupportedVersions(new byte[]{0x03, 0x04}); // TLS 1.3
//        clientHello.addExtension(supportedVersions);
//
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
