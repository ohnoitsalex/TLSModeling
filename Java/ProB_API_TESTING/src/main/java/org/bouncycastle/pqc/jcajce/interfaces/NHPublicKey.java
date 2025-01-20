package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;
import java.security.PublicKey;

public interface NHPublicKey
    extends PublicKey, Key {
    byte[] getPublicData();
}
