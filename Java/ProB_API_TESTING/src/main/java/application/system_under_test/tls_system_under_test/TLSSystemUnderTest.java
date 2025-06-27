package application.system_under_test.tls_system_under_test;

import application.config.Config;
import application.system_under_test.SystemUnderTest;

import java.io.IOException;

public class TLSSystemUnderTest extends SystemUnderTest {


    /* Mode of the TLS system under test, either "client" or "server".*/
    private String mode;

    
    /** Processes for the TLS SUT. */
    private Process sutProcess;

    public TLSSystemUnderTest(String mode) {
        this.mode = mode;
    }

    /**
     * Creates the System Under Test (SUT) by starting the TLS client or server process.
     * This method initializes the SUT based on the specified mode (client or server).
     */
    @Override
    public void createSUT() {
        try {
            if ("server".equalsIgnoreCase(mode)){
                // The SUT is the real server (ex: BouncyCastle)
                this.sutProcess = new ProcessBuilder("java", "-cp", Config.CLASSPATH, Config.SERVERCLASSNAME)
                    .inheritIO()
                    .start();
                System.out.println("TLS Server starting");
                Thread.sleep(10000); // Wait for 2 seconds - In order for the server to start properly
            } else if ("client".equalsIgnoreCase(mode)) {
                // The SUT is the real client
                this.sutProcess = new ProcessBuilder("java", "-cp", Config.CLASSPATH, Config.CLIENTCLASSNAME).
                    inheritIO().
                    start();
            } else {
                throw new IllegalArgumentException("Unknown mode: " + mode);
            }

            // this.sutProcess.waitFor(); // waiting for process to end.

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * Starts the System Under Test (SUT) in a separate thread.
     * This method is called to run the SUT without blocking the main thread.
     */
    @Override
    public void startSUT() {
        new Thread(this::createSUT).start();
    }

    /**
     * Executes the SUT operation.
     * This method is called to perform the main operation of the SUT.
     * In this case, it does nothing as the SUT is already running.
     */
    @Override
    public void executeSUTOperation() {

    }
}
