package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.security.Key;

public interface DilithiumKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a DilithiumParameterSpec
     */
    DilithiumParameterSpec getParameterSpec();
}
