package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputDecryptor;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.Key;
import java.security.PrivateKey;

public class JceKeyTransEnvelopedRecipient
        extends JceKeyTransRecipient {
    public JceKeyTransEnvelopedRecipient(PrivateKey recipientKey) {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
            throws CMSException {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor() {
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataIn) {
                return new CipherInputStream(dataIn, dataCipher);
            }
        });
    }
}
