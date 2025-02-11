package org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHPrivateKey;
import java.math.BigInteger;

public interface ElGamalPrivateKey
    extends ElGamalKey, DHPrivateKey
{
    public BigInteger getX();
}
