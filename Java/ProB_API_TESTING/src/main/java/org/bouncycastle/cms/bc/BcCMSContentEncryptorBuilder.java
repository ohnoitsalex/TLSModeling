package org.bouncycastle.cms.bc;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.operator.*;

import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

public class BcCMSContentEncryptorBuilder {
    private static final SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

    private final ASN1ObjectIdentifier encryptionOID;
    private final int keySize;

    private EnvelopedDataHelper helper = new EnvelopedDataHelper();
    private SecureRandom random;

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID) {
        this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID));
    }

    public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize) {
        this.encryptionOID = encryptionOID;
        int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

        if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC)) {
            if (keySize != 168 && keySize != fixedSize) {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 168;
        } else if (encryptionOID.equals(OIWObjectIdentifiers.desCBC)) {
            if (keySize != 56 && keySize != fixedSize) {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = 56;
        } else {
            if (fixedSize > 0 && fixedSize != keySize) {
                throw new IllegalArgumentException("incorrect keySize for encryptionOID passed to builder.");
            }
            this.keySize = keySize;
        }
    }

    public BcCMSContentEncryptorBuilder setSecureRandom(SecureRandom random) {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
            throws CMSException {
        if (helper.isAuthEnveloped(encryptionOID)) {
            return new CMSAuthOutputEncryptor(encryptionOID, keySize, random);
        }
        return new CMSOutputEncryptor(encryptionOID, keySize, random);
    }

    private static class AADStream
            extends OutputStream {
        private AEADBlockCipher cipher;

        public AADStream(AEADBlockCipher cipher) {
            this.cipher = cipher;
        }

        public void write(byte[] buf, int off, int len)
                throws IOException {
            cipher.processAADBytes(buf, off, len);
        }

        public void write(int b)
                throws IOException {
            cipher.processAADByte((byte) b);
        }
    }

    private class CMSOutputEncryptor
            implements OutputEncryptor {
        protected Object cipher;
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;

        CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
                throws CMSException {
            if (random == null) {
                random = new SecureRandom();
            }

            CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, keySize, random);

            encKey = new KeyParameter(keyGen.generateKey());

            algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);

            cipher = EnvelopedDataHelper.createContentCipher(true, encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut) {
            return CipherFactory.createOutputStream(dOut, cipher);
        }

        public GenericKey getKey() {
            return new GenericKey(algorithmIdentifier, encKey.getKey());
        }
    }

    private class CMSAuthOutputEncryptor
            extends CMSOutputEncryptor
            implements OutputAEADEncryptor {
        private AEADBlockCipher aeadCipher;
        private MacCaptureStream macOut;

        CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
                throws CMSException {
            super(encryptionOID, keySize, random);

            aeadCipher = getCipher();
        }

        private AEADBlockCipher getCipher() {
            if (!(cipher instanceof AEADBlockCipher)) {
                throw new IllegalArgumentException("Unable to create Authenticated Output Encryptor without Authenticaed Data cipher!");
            }
            return (AEADBlockCipher) cipher;
        }

        public OutputStream getOutputStream(OutputStream dOut) {
            macOut = new MacCaptureStream(dOut, aeadCipher.getMac().length);
            return CipherFactory.createOutputStream(macOut, cipher);
        }

        public OutputStream getAADStream() {
            return new AADStream(aeadCipher);
        }

        public byte[] getMAC() {
            return macOut.getMac();
        }
    }
}
