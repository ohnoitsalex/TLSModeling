package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.DigestedData;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * containing class for an CMS Digested Data object
 * <pre>
 *     CMSDigestedData cd = new CMSDigestedData(inputStream);
 *
 *
 *     process(cd.getContent());
 * </pre>
 */
public class CMSDigestedData
        implements Encodable {
    private final ContentInfo contentInfo;
    private final DigestedData digestedData;

    public CMSDigestedData(
            byte[] compressedData)
            throws CMSException {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSDigestedData(
            InputStream compressedData)
            throws CMSException {
        this(CMSUtils.readContentInfo(compressedData));
    }

    public CMSDigestedData(
            ContentInfo contentInfo)
            throws CMSException {
        this.contentInfo = contentInfo;

        try {
            this.digestedData = DigestedData.getInstance(contentInfo.getContent());
        } catch (ClassCastException e) {
            throw new CMSException("Malformed content.", e);
        } catch (IllegalArgumentException e) {
            throw new CMSException("Malformed content.", e);
        }
    }

    public ASN1ObjectIdentifier getContentType() {
        return contentInfo.getContentType();
    }

    public AlgorithmIdentifier getDigestAlgorithm() {
        return digestedData.getDigestAlgorithm();
    }

    /**
     * Return the digested content
     *
     * @return the digested content
     * @throws CMSException if there is an exception un-compressing the data.
     */
    public CMSProcessable getDigestedContent()
            throws CMSException {
        ContentInfo content = digestedData.getEncapContentInfo();

        try {
            return new CMSProcessableByteArray(content.getContentType(), ((ASN1OctetString) content.getContent()).getOctets());
        } catch (Exception e) {
            throw new CMSException("exception reading digested stream.", e);
        }
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure() {
        return contentInfo;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
            throws IOException {
        return contentInfo.getEncoded();
    }

    public boolean verify(DigestCalculatorProvider calculatorProvider)
            throws CMSException {
        try {
            ContentInfo content = digestedData.getEncapContentInfo();
            DigestCalculator calc = calculatorProvider.get(digestedData.getDigestAlgorithm());

            OutputStream dOut = calc.getOutputStream();

            dOut.write(((ASN1OctetString) content.getContent()).getOctets());

            return Arrays.areEqual(digestedData.getDigest(), calc.getDigest());
        } catch (OperatorCreationException e) {
            throw new CMSException("unable to create digest calculator: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new CMSException("unable process content: " + e.getMessage(), e);
        }
    }
}
