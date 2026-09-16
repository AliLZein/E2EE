package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class IdentityKeyPair {

    public final X25519PrivateKeyParameters dhPrivate;
    public final X25519PublicKeyParameters dhPublic;
    public final Ed25519PrivateKeyParameters signingPrivate;
    public final Ed25519PublicKeyParameters signingPublic;

    public IdentityKeyPair() {
        this.dhPrivate = KeyUtils.generateX25519PrivateKey();
        this.dhPublic = KeyUtils.derivePublic(dhPrivate);
        this.signingPrivate = KeyUtils.generateEd25519PrivateKey();
        this.signingPublic = KeyUtils.derivePublic(signingPrivate);
    }
}
