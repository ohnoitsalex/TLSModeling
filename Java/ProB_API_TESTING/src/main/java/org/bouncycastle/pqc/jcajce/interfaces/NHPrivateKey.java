package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;
import java.security.PrivateKey;

public interface NHPrivateKey
    extends PrivateKey, Key {
    short[] getSecretData();
}
