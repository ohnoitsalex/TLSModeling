package org.bouncycastle.cms;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

import java.math.BigInteger;

public class KeyTransRecipientId
        extends PKIXRecipientId {
    private KeyTransRecipientId(X509CertificateHolderSelector baseSelector) {
        super(keyTrans, baseSelector);
    }

    /**
     * Construct a key trans recipient ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public KeyTransRecipientId(byte[] subjectKeyId) {
        super(keyTrans, null, null, subjectKeyId);
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer       the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     */
    public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber) {
        super(keyTrans, issuer, serialNumber, null);
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer       the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     * @param subjectKeyId the subject key identifier to use to match the recipients associated certificate.
     */
    public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId) {
        super(keyTrans, issuer, serialNumber, subjectKeyId);
    }

    public boolean equals(
            Object o) {
        if (!(o instanceof KeyTransRecipientId id)) {
            return false;
        }

        return this.baseSelector.equals(id.baseSelector);
    }

    public Object clone() {
        return new KeyTransRecipientId(this.baseSelector);
    }

    public boolean match(Object obj) {
        if (obj instanceof KeyTransRecipientInformation) {
            return ((KeyTransRecipientInformation) obj).getRID().equals(this);
        }

        return super.match(obj);
    }
}
