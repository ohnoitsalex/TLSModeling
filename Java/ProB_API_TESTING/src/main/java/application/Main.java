package application;

import application.test_examiner.TestExaminer;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

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
