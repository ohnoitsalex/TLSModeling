package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;

import java.security.Key;

public interface FalconKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a FalconParameterSpec
     */
    FalconParameterSpec getParameterSpec();
}
