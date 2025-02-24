package org.bouncycastle.jce.interfaces;

import javax.crypto.interfaces.DHPublicKey;
import java.math.BigInteger;

/**
 * @deprecated just use DHPublicKey.
 */
public interface ElGamalPublicKey
    extends ElGamalKey, DHPublicKey
{
    public BigInteger getY();
}
