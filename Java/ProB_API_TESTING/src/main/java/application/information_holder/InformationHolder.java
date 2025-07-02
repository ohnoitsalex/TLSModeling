package application.information_holder;

/**
 * Abstract base class for holding structured information extracted from TLS messages.
 * This class serves as the foundation for concrete information holder implementations
 * that store and manage data from various TLS protocol messages during Model-Based Testing.
 * 
 * <p>Information holders are used to:
 * <ul>
 *   <li>Store abstracted data from TLS handshake messages</li>
 *   <li>Provide a standardized structure for message data comparison</li>
 *   <li>Enable serialization to YAML format for testing and validation</li>
 *   <li>Support both model-generated and SUT-generated message data</li>
 * </ul>
 * 
 * @author TLSModeling Team
 * @version 1.0
 * @since 1.0
 */
public abstract class InformationHolder {

    /**
     * Default constructor for InformationHolder.
     * Initializes the base information holder structure.
     */
    public InformationHolder() {

    }
}
