package org.bouncycastle.pqc.jcajce.interfaces;

import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;

import java.security.Key;

public interface BIKEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a BIKEParameterSpec
     */
    BIKEParameterSpec getParameterSpec();
}
