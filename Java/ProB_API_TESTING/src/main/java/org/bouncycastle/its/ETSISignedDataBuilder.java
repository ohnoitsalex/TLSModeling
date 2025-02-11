package org.bouncycastle.its;

import org.bouncycastle.its.operator.ECDSAEncoder;
import org.bouncycastle.its.operator.ITSContentSigner;
import org.bouncycastle.oer.Element;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.ieee1609dot2.*;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.*;
import org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;

import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class ETSISignedDataBuilder
{
    private static final Element def = IEEE1609dot2.ToBeSignedData.build();

    private final HeaderInfo headerInfo;

    private Ieee1609Dot2Data data;
    private HashedData extDataHash;

    private ETSISignedDataBuilder(Psid psid)
    {
        this(HeaderInfo.builder().setPsid(psid).setGenerationTime(Time64.now()).createHeaderInfo());
    }

    private ETSISignedDataBuilder(HeaderInfo headerInfo)
    {
        this.headerInfo = headerInfo;
    }

    public static ETSISignedDataBuilder builder(Psid psid)
    {
        return new ETSISignedDataBuilder(psid);
    }

    public static ETSISignedDataBuilder builder(HeaderInfo headerInfo)
    {
        return new ETSISignedDataBuilder(headerInfo);
    }

    public ETSISignedDataBuilder setData(Ieee1609Dot2Content data)
    {
        this.data = Ieee1609Dot2Data.builder()
            .setProtocolVersion(new UINT8(3))
            .setContent(data).createIeee1609Dot2Data();
        return this;
    }

    public ETSISignedDataBuilder setUnsecuredData(byte[] data)
    {
        this.data = Ieee1609Dot2Data.builder()
            .setProtocolVersion(new UINT8(3))
            .setContent(Ieee1609Dot2Content
                .unsecuredData( new Opaque(data))).createEtsiTs103097Data();
        return this;
    }

    public ETSISignedDataBuilder setExtDataHash(HashedData extDataHash)
    {
        this.extDataHash = extDataHash;
        return this;
    }

    private ToBeSignedData getToBeSignedData()
    {
        SignedDataPayload signedDataPayload = new SignedDataPayload(data, extDataHash);

        return ToBeSignedData.builder()
            .setPayload(signedDataPayload)
            .setHeaderInfo(headerInfo)
            .createToBeSignedData();
    }


    /**
     * Self signed
     *
     * @param signer
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer)
    {
        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.self())
            .setSignature(signature).createSignedData());
    }

    /**
     * Ceritificate
     *
     * @param signer
     * @param certificateList
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer, List<ITSCertificate> certificateList)
    {
        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        List<Certificate> certificates = new ArrayList<Certificate>();
        for (ITSCertificate certificate : certificateList)
        {
            certificates.add(Certificate.getInstance(certificate.toASN1Structure()));
        }

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.certificate(new SequenceOfCertificate(certificates)))
            .setSignature(signature).createSignedData());
    }

    /**
     * Hash id
     *
     * @param signer
     * @param identifier
     * @return
     */
    public ETSISignedData build(ITSContentSigner signer, HashedId8 identifier)
    {

        ToBeSignedData toBeSignedData = getToBeSignedData();
        write(signer.getOutputStream(), OEREncoder.toByteArray(toBeSignedData, def));

        Signature signature = ECDSAEncoder.toITS(signer.getCurveID(), signer.getSignature());

        return new ETSISignedData(SignedData.builder()
            .setHashId(ITSAlgorithmUtils.getHashAlgorithm(signer.getDigestAlgorithm().getAlgorithm()))
            .setTbsData(toBeSignedData)
            .setSigner(SignerIdentifier.digest(identifier))
            .setSignature(signature).createSignedData());
    }

    private static void write(OutputStream os, byte[] data)
    {
        try
        {
            os.write(data);
            os.flush();
            os.close();
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }
}
