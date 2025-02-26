package org.bouncycastle.cms.jcajce;

import org.bouncycastle.cms.KeyTransRecipientId;
import org.bouncycastle.cms.SignerId;

import java.security.cert.X509CertSelector;

public class JcaX509CertSelectorConverter
        extends org.bouncycastle.cert.selector.jcajce.JcaX509CertSelectorConverter {
    public JcaX509CertSelectorConverter() {
    }

    public X509CertSelector getCertSelector(KeyTransRecipientId recipientId) {
        return doConversion(recipientId.getIssuer(), recipientId.getSerialNumber(), recipientId.getSubjectKeyIdentifier());
    }

    public X509CertSelector getCertSelector(SignerId signerId) {
        return doConversion(signerId.getIssuer(), signerId.getSerialNumber(), signerId.getSubjectKeyIdentifier());
    }
}
