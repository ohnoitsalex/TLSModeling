package org.bouncycastle.cms.jcajce;


import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;

import java.security.*;

public class JceAlgorithmIdentifierConverter {
    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private SecureRandom random;

    public JceAlgorithmIdentifierConverter() {
    }

    public JceAlgorithmIdentifierConverter setProvider(Provider provider) {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    public JceAlgorithmIdentifierConverter setProvider(String providerName) {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

        return this;
    }

    public AlgorithmParameters getAlgorithmParameters(AlgorithmIdentifier algorithmIdentifier)
            throws CMSException {
        ASN1Encodable parameters = algorithmIdentifier.getParameters();

        if (parameters == null) {
            return null;
        }

        try {
            AlgorithmParameters params = helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());

            CMSUtils.loadParameters(params, algorithmIdentifier.getParameters());

            return params;
        } catch (NoSuchAlgorithmException e) {
            throw new CMSException("can't find parameters for algorithm", e);
        } catch (NoSuchProviderException e) {
            throw new CMSException("can't find provider for algorithm", e);
        }
    }
}
