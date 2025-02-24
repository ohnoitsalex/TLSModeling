package org.bouncycastle.its.operator;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.*;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;

public class ECDSAEncoder
{
    public static byte[] toX962(Signature signature)
    {
        byte[] r;
        byte[] s;
        if (signature.getChoice() == Signature.ecdsaNistP256Signature || signature.getChoice() == Signature.ecdsaBrainpoolP256r1Signature)
        {
            EcdsaP256Signature sig = EcdsaP256Signature.getInstance(signature.getSignature());
            r = ASN1OctetString.getInstance(sig.getRSig().getEccp256CurvePoint()).getOctets();
            s = sig.getSSig().getOctets();
        }
        else
        {
            EcdsaP384Signature sig = EcdsaP384Signature.getInstance(signature.getSignature());
            r = ASN1OctetString.getInstance(sig.getRSig().getEccP384CurvePoint()).getOctets();
            s = sig.getSSig().getOctets();
        }

        try
        {
            return new DERSequence(new ASN1Encodable[]{new ASN1Integer(BigIntegers.fromUnsignedByteArray(r)),
                new ASN1Integer(BigIntegers.fromUnsignedByteArray(s))}).getEncoded();
        }
        catch (IOException ioException)
        {
            throw new RuntimeException("der encoding r & s");
        }
    }

    public static Signature toITS(ASN1ObjectIdentifier curveID, byte[] dsaEncoding)
    {
        ASN1Sequence asn1Sig = ASN1Sequence.getInstance(dsaEncoding);

        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            return new Signature(Signature.ecdsaNistP256Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP256r1Signature, new EcdsaP256Signature(
                new EccP256CurvePoint(EccP256CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(32, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }
        if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            return new Signature(Signature.ecdsaBrainpoolP384r1Signature, new EcdsaP384Signature(
                new EccP384CurvePoint(EccP384CurvePoint.xonly, new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(0)).getValue()))),
                new DEROctetString(BigIntegers.asUnsignedByteArray(48, ASN1Integer.getInstance(asn1Sig.getObjectAt(1)).getValue()))));
        }

        throw new IllegalArgumentException("unknown curveID");
    }
}
