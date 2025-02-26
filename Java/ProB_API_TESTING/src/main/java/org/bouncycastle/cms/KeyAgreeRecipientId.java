package org.bouncycastle.cms;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

import java.math.BigInteger;

public class KeyAgreeRecipientId
        extends PKIXRecipientId {
    private KeyAgreeRecipientId(X509CertificateHolderSelector baseSelector) {
        super(keyAgree, baseSelector);
    }

    /**
     * Construct a key agree recipient ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public KeyAgreeRecipientId(byte[] subjectKeyId) {
        super(keyAgree, null, null, subjectKeyId);
    }

    /**
     * Construct a key agree recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer       the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     */
    public KeyAgreeRecipientId(X500Name issuer, BigInteger serialNumber) {
        super(keyAgree, issuer, serialNumber, null);
    }

    public KeyAgreeRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId) {
        super(keyAgree, issuer, serialNumber, subjectKeyId);
    }

    public X500Name getIssuer() {
        return baseSelector.getIssuer();
    }

    public BigInteger getSerialNumber() {
        return baseSelector.getSerialNumber();
    }

    public byte[] getSubjectKeyIdentifier() {
        return baseSelector.getSubjectKeyIdentifier();
    }

    public int hashCode() {
        return baseSelector.hashCode();
    }

    public boolean equals(
            Object o) {
        if (!(o instanceof KeyAgreeRecipientId id)) {
            return false;
        }

        return this.baseSelector.equals(id.baseSelector);
    }

    public Object clone() {
        return new KeyAgreeRecipientId(baseSelector);
    }

    public boolean match(Object obj) {
        if (obj instanceof KeyAgreeRecipientInformation) {
            return ((KeyAgreeRecipientInformation) obj).getRID().equals(this);
        }

        return baseSelector.match(obj);
    }
}
