package org.bouncycastle.cms;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.util.Arrays;

import java.security.SecureRandom;

public abstract class PasswordRecipientInfoGenerator
        implements RecipientInfoGenerator {
    private final ASN1ObjectIdentifier kekAlgorithm;
    private final int keySize;
    private final int blockSize;
    protected char[] password;
    private AlgorithmIdentifier keyDerivationAlgorithm;
    private SecureRandom random;
    private int schemeID;
    private PasswordRecipient.PRF prf;
    private byte[] salt;
    private int iterationCount;

    protected PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) {
        this(kekAlgorithm, password, getKeySize(kekAlgorithm), ((Integer) PasswordRecipientInformation.BLOCKSIZES.get(kekAlgorithm)).intValue());
    }

    protected PasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password, int keySize, int blockSize) {
        this.password = password;
        this.schemeID = PasswordRecipient.PKCS5_SCHEME2_UTF8;
        this.kekAlgorithm = kekAlgorithm;
        this.keySize = keySize;
        this.blockSize = blockSize;
        this.prf = PasswordRecipient.PRF.HMacSHA1;
        this.iterationCount = 1024;
    }

    private static int getKeySize(ASN1ObjectIdentifier kekAlgorithm) {
        Integer size = (Integer) PasswordRecipientInformation.KEYSIZES.get(kekAlgorithm);

        if (size == null) {
            throw new IllegalArgumentException("cannot find key size for algorithm: " + kekAlgorithm);
        }

        return size.intValue();
    }

    public PasswordRecipientInfoGenerator setPasswordConversionScheme(int schemeID) {
        this.schemeID = schemeID;

        return this;
    }

    public PasswordRecipientInfoGenerator setPRF(PasswordRecipient.PRF prf) {
        this.prf = prf;

        return this;
    }

    public PasswordRecipientInfoGenerator setSaltAndIterationCount(byte[] salt, int iterationCount) {
        this.salt = Arrays.clone(salt);
        this.iterationCount = iterationCount;

        return this;
    }

    public PasswordRecipientInfoGenerator setSecureRandom(SecureRandom random) {
        this.random = random;

        return this;
    }

    public RecipientInfo generate(GenericKey contentEncryptionKey)
            throws CMSException {
        byte[] iv = new byte[blockSize];     /// TODO: set IV size properly!

        if (random == null) {
            random = new SecureRandom();
        }

        random.nextBytes(iv);

        if (salt == null) {
            salt = new byte[20];

            random.nextBytes(salt);
        }

        keyDerivationAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount, prf.prfAlgID));

        byte[] derivedKey = calculateDerivedKey(schemeID, keyDerivationAlgorithm, keySize);

        AlgorithmIdentifier kekAlgorithmId = new AlgorithmIdentifier(kekAlgorithm, new DEROctetString(iv));

        byte[] encryptedKeyBytes = generateEncryptedBytes(kekAlgorithmId, derivedKey, contentEncryptionKey);

        ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(kekAlgorithm);
        v.add(new DEROctetString(iv));

        AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
                PKCSObjectIdentifiers.id_alg_PWRI_KEK, new DERSequence(v));

        return new RecipientInfo(new PasswordRecipientInfo(keyDerivationAlgorithm,
                keyEncryptionAlgorithm, encryptedKey));
    }

    protected abstract byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
            throws CMSException;

    protected abstract byte[] generateEncryptedBytes(AlgorithmIdentifier algorithm, byte[] derivedKey, GenericKey contentEncryptionKey)
            throws CMSException;
}