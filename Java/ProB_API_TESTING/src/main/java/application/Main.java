package application;

import application.test_examiner.TestExaminer;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Main entry point for the TLSModeling Model-Based Testing framework.
 * This class initializes the testing environment and launches the TLS protocol
 * validation process using formal B-method specifications against real TLS implementations.
 * 
 * <p>The framework performs Model-Based Testing by:
 * <ul>
 *   <li>Loading and executing formal B-machine models of TLS 1.3</li>
 *   <li>Generating test cases from the model specifications</li>
 *   <li>Executing these tests against System Under Test implementations</li>
 *   <li>Comparing model outputs with SUT behaviors for validation</li>
 * </ul>
 * 
 */
public class Main {

    /**
     * Main method that starts the TLS Model-Based Testing process.
     * Registers the BouncyCastle cryptographic provider and initializes 
     * the TestExaminer with TLS model configuration.
     * 
     * @param args command line arguments (currently not used)
     */
    public static void main(String[] args) {
        // Example : we test a real server with a TLS-Attacker client

        // Register BouncyCastle provider
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String type = "tls"; // Model choice

        TestExaminer examiner = new TestExaminer(type);
        examiner.runTest();
    }
}
