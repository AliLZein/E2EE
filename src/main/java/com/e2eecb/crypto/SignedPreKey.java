package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class SignedPreKey {

    public final int id;
    public final X25519PrivateKeyParameters privateKey;
    public final X25519PublicKeyParameters publicKey;
    public final byte[] signature;

    public SignedPreKey(int id, IdentityKeyPair identity) {
        this.id = id;
        this.privateKey = KeyUtils.generateX25519PrivateKey();
        this.publicKey = KeyUtils.derivePublic(privateKey);
        this.signature = KeyUtils.sign(identity.signingPrivate, KeyUtils.encode(publicKey));
    }
}
