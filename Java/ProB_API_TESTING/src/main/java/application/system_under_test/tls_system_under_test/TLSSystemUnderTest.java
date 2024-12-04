package application.system_under_test.tls_system_under_test;

import application.information_capture.tls_information_capture.TLSInformationCapture;
import application.system_under_test.SystemUnderTest;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import java.io.IOException;

public class TLSSystemUnderTest {
    private Process serverProcess, clientProcess;

    private final String clientClassName = "application.system_under_test.tls_system_under_test.Client";
    private final String serverClassName = "application.system_under_test.tls_system_under_test.Server";
    private final String classPath = "/Users/alex/Desktop/School/Masters/Projet de Recherche/Code/ALL CODE/TLSModeling/Java/ProB_API_TESTING/target/classes";

    private TLSInformationCapture informationCapture;
    public TLSSystemUnderTest (){
        informationCapture = new TLSInformationCapture();
    }

    public void createSUT() {
        try {
            this.serverProcess  = new ProcessBuilder( "java", "-cp", classPath, serverClassName).inheritIO().start();
            Thread.sleep(3000);  // Wait for 3 seconds (3000 milliseconds) - In order for the server to start properly
            this.clientProcess  = new ProcessBuilder( "java", "-cp", classPath, clientClassName).inheritIO().start();
            this.serverProcess.waitFor();
            this.clientProcess.waitFor();

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

    }

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

        // Create two threads for each task
        Thread thread1 = new Thread(task1);
        Thread thread2 = new Thread(task2);

        // Start the threads
        thread1.start();
        thread2.start();

        //informationCapture.startCapture(); //Startin capture before the SUT in order to properly get all the information
        //this.createSUT(); //This java implementation creates and starts the process at the same time...
    }

    public void executeSUTOperation() {

    }
}
