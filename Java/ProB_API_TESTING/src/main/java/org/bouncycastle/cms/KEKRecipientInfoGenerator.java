package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.SymmetricKeyWrapper;

public abstract class KEKRecipientInfoGenerator
        implements RecipientInfoGenerator {
    protected final SymmetricKeyWrapper wrapper;
    private final KEKIdentifier kekIdentifier;

    protected KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SymmetricKeyWrapper wrapper) {
        this.kekIdentifier = kekIdentifier;
        this.wrapper = wrapper;
    }

    public final RecipientInfo generate(GenericKey contentEncryptionKey)
            throws CMSException {
        try {
            ASN1OctetString encryptedKey = new DEROctetString(wrapper.generateWrappedKey(contentEncryptionKey));

            return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, wrapper.getAlgorithmIdentifier(), encryptedKey));
        } catch (OperatorException e) {
            throw new CMSException("exception wrapping content key: " + e.getMessage(), e);
        }
    }
}