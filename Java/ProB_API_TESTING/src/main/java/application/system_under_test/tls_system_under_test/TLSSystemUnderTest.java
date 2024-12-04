package application.system_under_test.tls_system_under_test;

import application.information_capture.InformationCapture;
import application.information_capture.tls_information_capture.TLSInformationCapture;
import application.system_under_test.SystemUnderTest;

import java.io.IOException;

public class TLSSystemUnderTest extends SystemUnderTest {
    private final String clientClassName = "application.system_under_test.tls_system_under_test.Client";
    private final String serverClassName = "application.system_under_test.tls_system_under_test.Server";
    private final String classPath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/target/classes";
    private Process serverProcess, clientProcess;
    private InformationCapture informationCapture;

    public TLSSystemUnderTest() {
        informationCapture = new TLSInformationCapture();
    }

    @Override
    public void createSUT() {
        try {
            this.serverProcess = new ProcessBuilder("java", "-cp", classPath, serverClassName).inheritIO().start();
            Thread.sleep(2000);  // Wait for 2 seconds (2000 milliseconds) - In order for the server to start properly
            this.clientProcess = new ProcessBuilder("java", "-cp", classPath, clientClassName).inheritIO().start();
            this.serverProcess.waitFor();
            this.clientProcess.waitFor();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

    }
    @Override
    public void startSUT() {

        // Create the first Runnable for startCapture
        Runnable task1 = new Runnable() {
            @Override
            public void run() {
                informationCapture.startCapture();
            }
        };

        // Create the second Runnable for createSUT
        Runnable task2 = new Runnable() {
            @Override
            public void run() {
                createSUT(); // Assuming createSUT is a static method or method in the current class
            }
        };

        // Create two threads for each task - It takes a bit of time before the .txt file is generated.
        Thread thread1 = new Thread(task1);
        Thread thread2 = new Thread(task2);

        // Start the threads
        thread1.start();
        thread2.start();
    }
    @Override
    public void executeSUTOperation() {

    }
}
