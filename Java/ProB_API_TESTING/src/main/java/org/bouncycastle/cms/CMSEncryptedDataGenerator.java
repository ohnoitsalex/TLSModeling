package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EncryptedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OutputEncryptor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * General class for generating a CMS encrypted-data message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
 *
 *       CMSEncryptedDataGenerator edGen = new CMSEncryptedDataGenerator();
 *
 *       CMSEncryptedData ed = edGen.generate(
 *                                       msg,
 *                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *
 * </pre>
 */
public class CMSEncryptedDataGenerator
        extends CMSEncryptedGenerator {
    /**
     * base constructor
     */
    public CMSEncryptedDataGenerator() {
    }

    private CMSEncryptedData doGenerate(
            CMSTypedData content,
            OutputEncryptor contentEncryptor)
            throws CMSException {
        AlgorithmIdentifier encAlgId;
        ASN1OctetString encContent;

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);

            content.write(cOut);

            cOut.close();
        } catch (IOException e) {
            throw new CMSException("");
        }

        byte[] encryptedContent = bOut.toByteArray();

        encAlgId = contentEncryptor.getAlgorithmIdentifier();

        encContent = new BEROctetString(encryptedContent);

        EncryptedContentInfo eci = CMSUtils.getEncryptedContentInfo(
                content.getContentType(),
                encAlgId,
                encryptedContent);

        ASN1Set unprotectedAttrSet = CMSUtils.getAttrBERSet(unprotectedAttributeGenerator);

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.encryptedData,
                new EncryptedData(eci, unprotectedAttrSet));

        return new CMSEncryptedData(contentInfo);
    }

    /**
     * generate an encrypted object that contains an CMS Encrypted Data structure.
     *
     * @param content          the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSEncryptedData generate(
            CMSTypedData content,
            OutputEncryptor contentEncryptor)
            throws CMSException {
        return doGenerate(content, contentEncryptor);
    }
}
