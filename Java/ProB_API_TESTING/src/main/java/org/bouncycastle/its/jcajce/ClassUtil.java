package org.bouncycastle.its.jcajce;

import javax.crypto.spec.GCMParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

class ClassUtil
{
    public static AlgorithmParameterSpec getGCMSpec(final byte[] nonce, final int tagSize)
    {
        // GCMParameterSpec arrived in Java 7.
        return new GCMParameterSpec(tagSize, nonce);
    }
}
