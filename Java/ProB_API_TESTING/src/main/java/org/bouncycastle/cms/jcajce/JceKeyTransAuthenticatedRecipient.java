package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.MacOutputStream;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JceGenericKey;

import javax.crypto.Mac;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class JceKeyTransAuthenticatedRecipient
        extends JceKeyTransRecipient {
    public JceKeyTransAuthenticatedRecipient(PrivateKey recipientKey) {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
            throws CMSException {
        final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);

        final Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new MacCalculator() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return contentMacAlgorithm;
            }

            public GenericKey getKey() {
                return new JceGenericKey(contentMacAlgorithm, secretKey);
            }

            public OutputStream getOutputStream() {
                return new MacOutputStream(dataMac);
            }

            public byte[] getMac() {
                return dataMac.doFinal();
            }
        });
    }
}
