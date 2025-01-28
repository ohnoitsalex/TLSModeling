package org.bouncycastle.pkcs.jcajce;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;

import java.security.PrivateKey;

public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder
{
    public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey)
    {
         super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
