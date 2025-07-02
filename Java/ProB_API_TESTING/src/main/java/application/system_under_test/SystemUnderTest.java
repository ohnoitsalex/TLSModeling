package application.system_under_test;

/**
 * Abstract base class for all System Under Test (SUT) implementations.
 * This class defines the standard interface that all concrete SUT implementations
 * must follow for Model-Based Testing of TLS protocols.
 * 
 * <p>Implementations of this class represent actual TLS protocol implementations
 * that will be tested against formal B-method specifications. Examples include
 * TLS-Attacker based implementations, Bouncy Castle providers, or OpenSSL bindings.
 * 
 */
public abstract class SystemUnderTest {

    /**
     * Creates and initializes the System Under Test.
     * This method should set up all necessary resources, configurations,
     * and dependencies required for the SUT to operate properly.
     */
    public abstract void createSUT();

    /**
     * Starts the System Under Test execution.
     * This method should begin the SUT's operation, such as starting
     * a server listener, initializing client connections, or beginning
     * message processing.
     */
    public abstract void startSUT();

    /**
     * Executes a specific operation on the System Under Test.
     * This method should perform the main testing operation, such as
     * sending/receiving TLS messages, processing handshake sequences,
     * or handling specific protocol scenarios.
     */
    public abstract void executeSUTOperation();

}
