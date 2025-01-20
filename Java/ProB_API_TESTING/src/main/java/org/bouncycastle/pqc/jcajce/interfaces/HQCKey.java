package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;

import java.security.Key;

public interface HQCKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a HQCParameterSpec
     */
    HQCParameterSpec getParameterSpec();
}
