package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.crypto.util.CipherKeyGeneratorFactory;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestProvider;

import java.security.SecureRandom;
import java.util.*;

class EnvelopedDataHelper {
    protected static final Map BASE_CIPHER_NAMES = new HashMap();
    protected static final Map MAC_ALG_NAMES = new HashMap();

    private static final Set authEnvelopedAlgorithms = new HashSet();
    private static final Map prfs = createTable();

    static {
        BASE_CIPHER_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDE");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES128_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES192_CBC, "AES");
        BASE_CIPHER_NAMES.put(CMSAlgorithm.AES256_CBC, "AES");

        MAC_ALG_NAMES.put(CMSAlgorithm.DES_EDE3_CBC, "DESEDEMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES128_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES192_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.AES256_CBC, "AESMac");
        MAC_ALG_NAMES.put(CMSAlgorithm.RC2_CBC, "RC2Mac");

        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes128_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes192_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes256_GCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes128_CCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes192_CCM);
        authEnvelopedAlgorithms.add(NISTObjectIdentifiers.id_aes256_CCM);
    }

    EnvelopedDataHelper() {
    }

    private static Map createTable() {
        Map table = new HashMap();

        table.put(PKCSObjectIdentifiers.id_hmacWithSHA1, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA1Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA224, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA224Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA256, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return SHA256Digest.newInstance();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA384, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA384Digest();
            }
        });
        table.put(PKCSObjectIdentifiers.id_hmacWithSHA512, new BcDigestProvider() {
            public ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier) {
                return new SHA512Digest();
            }
        });

        return Collections.unmodifiableMap(table);
    }

    static ExtendedDigest getPRF(AlgorithmIdentifier algID)
            throws OperatorCreationException {
        return ((BcDigestProvider) prfs.get(algID.getAlgorithm())).get(null);
    }

    static Wrapper createRFC3211Wrapper(ASN1ObjectIdentifier algorithm)
            throws CMSException {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm)
                || NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm)
                || NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm)) {
            return new RFC3211WrapEngine(AESEngine.newInstance());
        } else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm)) {
            return new RFC3211WrapEngine(new DESedeEngine());
        } else if (OIWObjectIdentifiers.desCBC.equals(algorithm)) {
            return new RFC3211WrapEngine(new DESEngine());
        } else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm)) {
            return new RFC3211WrapEngine(new RC2Engine());
        } else {
            throw new CMSException("cannot recognise wrapper: " + algorithm);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
            throws CMSException {
        try {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        } catch (IllegalArgumentException e) {
            throw new CMSException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
            throws CMSException {
        try {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        } catch (IllegalArgumentException e) {
            throw new CMSException(e.getMessage(), e);
        }
    }

    // TODO: make use of keySize parameter.
    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, int keySize, SecureRandom random)
            throws CMSException {
        try {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        } catch (IllegalArgumentException e) {
            throw new CMSException(e.getMessage(), e);
        }
    }

    boolean isAuthEnveloped(ASN1ObjectIdentifier algorithm) {
        return authEnvelopedAlgorithms.contains(algorithm);
    }
}
