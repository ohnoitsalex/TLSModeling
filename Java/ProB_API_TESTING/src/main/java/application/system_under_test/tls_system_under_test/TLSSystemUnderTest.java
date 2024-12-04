package application.system_under_test.tls_system_under_test;

import application.config.Config;
import application.information_capture.InformationCapture;
import application.information_capture.tls_information_capture.TLSInformationCapture;
import application.system_under_test.SystemUnderTest;

import java.io.IOException;

public class TLSSystemUnderTest extends SystemUnderTest {
    private Process serverProcess, clientProcess;
    private InformationCapture informationCapture;

    public TLSSystemUnderTest() {
        informationCapture = new TLSInformationCapture();
    }

    @Override
    public void createSUT() {
        try {
            this.serverProcess = new ProcessBuilder("java", "-cp", Config.CLASSPATH, Config.SERVERCLASSNAME).inheritIO().start();
            Thread.sleep(2000);  // Wait for 2 seconds (2000 milliseconds) - In order for the server to start properly
            this.clientProcess = new ProcessBuilder("java", "-cp", Config.CLASSPATH, Config.CLIENTCLASSNAME).inheritIO().start();
            this.serverProcess.waitFor();
            this.clientProcess.waitFor();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void startSUT() {

        // Create the first Runnable for startCapture
        Runnable information_capture = new Runnable() {
            @Override
            public void run() {
                informationCapture.startCapture();
            }
        };

        // Create the second Runnable for createSUT
        Runnable createSystemUnderTest = new Runnable() {
            @Override
            public void run() {
                createSUT(); // Assuming createSUT is a static method or method in the current class
            }
        };

        // Create two threads for each task - It takes a bit of time before the .txt file is generated.
        Thread thread1 = new Thread(information_capture);
        Thread thread2 = new Thread(createSystemUnderTest);

        // Start the threads
        thread1.start();
        thread2.start();
    }

    @Override
    public void executeSUTOperation() {

    }
}
