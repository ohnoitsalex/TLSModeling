package org.bouncycastle.cms.jcajce;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import org.bouncycastle.operator.SymmetricKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceKTSKeyUnwrapper;
import org.bouncycastle.operator.jcajce.JceSymmetricKeyUnwrapper;

import javax.crypto.SecretKey;
import java.security.PrivateKey;

class NamedJcaJceExtHelper
        extends NamedJcaJceHelper
        implements JcaJceExtHelper {
    public NamedJcaJceExtHelper(String providerName) {
        super(providerName);
    }

    public JceAsymmetricKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey) {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey).setProvider(providerName);
    }

    public JceKTSKeyUnwrapper createAsymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey, byte[] partyUInfo, byte[] partyVInfo) {
        keyEncryptionKey = CMSUtils.cleanPrivateKey(keyEncryptionKey);
        return new JceKTSKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey, partyUInfo, partyVInfo).setProvider(providerName);
    }

    public SymmetricKeyUnwrapper createSymmetricUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, SecretKey keyEncryptionKey) {
        return new JceSymmetricKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey).setProvider(providerName);
    }

    public AsymmetricKeyUnwrapper createKEMUnwrapper(AlgorithmIdentifier keyEncryptionAlgorithm, PrivateKey keyEncryptionKey) {
        return new JceCMSKEMKeyUnwrapper(keyEncryptionAlgorithm, keyEncryptionKey).setProvider(providerName);
    }
}