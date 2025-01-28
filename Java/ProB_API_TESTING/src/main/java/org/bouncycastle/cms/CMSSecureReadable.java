package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;

import java.io.IOException;
import java.io.InputStream;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;

    ASN1Set getAuthAttrSet();

    void setAuthAttrSet(ASN1Set set);

    boolean hasAdditionalData();
}
