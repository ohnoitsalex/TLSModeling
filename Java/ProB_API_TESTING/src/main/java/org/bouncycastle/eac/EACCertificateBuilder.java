package org.bouncycastle.eac;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.eac.*;
import org.bouncycastle.eac.operator.EACSigner;

import java.io.OutputStream;

public class EACCertificateBuilder
{
    private static final byte [] ZeroArray = new byte [] {0};

    private final PublicKeyDataObject publicKey;
    private final CertificateHolderAuthorization certificateHolderAuthorization;
    private final PackedDate certificateEffectiveDate;
    private final PackedDate certificateExpirationDate;
    private final CertificateHolderReference certificateHolderReference;
    private final CertificationAuthorityReference certificationAuthorityReference;

    public EACCertificateBuilder(
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate)
    {
        this.certificationAuthorityReference = certificationAuthorityReference;
        this.publicKey = publicKey;
        this.certificateHolderReference = certificateHolderReference;
        this.certificateHolderAuthorization = certificateHolderAuthorization;
        this.certificateEffectiveDate = certificateEffectiveDate;
        this.certificateExpirationDate = certificateExpirationDate;
    }

    private CertificateBody buildBody()
    {
        ASN1TaggedObject certificateProfileIdentifier;

        certificateProfileIdentifier = new DERTaggedObject(false, BERTags.APPLICATION,
                EACTags.INTERCHANGE_PROFILE, new DEROctetString(ZeroArray));

        CertificateBody body = new CertificateBody(
                certificateProfileIdentifier,
                certificationAuthorityReference,
                publicKey,
                certificateHolderReference,
                certificateHolderAuthorization,
                certificateEffectiveDate,
                certificateExpirationDate);

        return body;
    }

    public EACCertificateHolder build(EACSigner signer)
        throws EACException
    {
        try
        {
            CertificateBody body = buildBody();

            OutputStream vOut = signer.getOutputStream();

            vOut.write(body.getEncoded(ASN1Encoding.DER));

            vOut.close();

            return new EACCertificateHolder(new CVCertificate(body, signer.getSignature()));
        }
        catch (Exception e)
        {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
