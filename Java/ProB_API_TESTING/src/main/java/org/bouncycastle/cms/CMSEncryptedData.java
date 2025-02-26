package org.bouncycastle.cms;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EncryptedData;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class CMSEncryptedData {
    private final ContentInfo contentInfo;
    private final EncryptedData encryptedData;

    public CMSEncryptedData(ContentInfo contentInfo) {
        this.contentInfo = contentInfo;

        this.encryptedData = EncryptedData.getInstance(contentInfo.getContent());
    }

    public byte[] getContent(InputDecryptorProvider inputDecryptorProvider)
            throws CMSException {
        try {
            return CMSUtils.streamToByteArray(getContentStream(inputDecryptorProvider).getContentStream());
        } catch (IOException e) {
            throw new CMSException("unable to parse internal stream: " + e.getMessage(), e);
        }
    }

    public CMSTypedStream getContentStream(InputDecryptorProvider inputDecryptorProvider)
            throws CMSException {
        try {
            EncryptedContentInfo encContentInfo = encryptedData.getEncryptedContentInfo();
            InputDecryptor decrytor = inputDecryptorProvider.get(encContentInfo.getContentEncryptionAlgorithm());

            ByteArrayInputStream encIn = new ByteArrayInputStream(encContentInfo.getEncryptedContent().getOctets());

            return new CMSTypedStream(encContentInfo.getContentType(), decrytor.getInputStream(encIn));
        } catch (Exception e) {
            throw new CMSException("unable to create stream: " + e.getMessage(), e);
        }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure() {
        return contentInfo;
    }
}
