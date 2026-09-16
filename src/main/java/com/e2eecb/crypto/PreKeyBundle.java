package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class PreKeyBundle {

    public final String userId;
    public final X25519PublicKeyParameters identityDhPublic;
    public final Ed25519PublicKeyParameters identitySigningPublic;
    public final int signedPreKeyId;
    public final X25519PublicKeyParameters signedPreKeyPublic;
    public final byte[] signedPreKeySignature;
    public final Integer oneTimePreKeyId;
    public final X25519PublicKeyParameters oneTimePreKeyPublic;

    public PreKeyBundle(String userId, X25519PublicKeyParameters identityDhPublic, Ed25519PublicKeyParameters identitySigningPublic,
                         int signedPreKeyId, X25519PublicKeyParameters signedPreKeyPublic, byte[] signedPreKeySignature,
                         Integer oneTimePreKeyId, X25519PublicKeyParameters oneTimePreKeyPublic) {
        this.userId = userId;
        this.identityDhPublic = identityDhPublic;
        this.identitySigningPublic = identitySigningPublic;
        this.signedPreKeyId = signedPreKeyId;
        this.signedPreKeyPublic = signedPreKeyPublic;
        this.signedPreKeySignature = signedPreKeySignature;
        this.oneTimePreKeyId = oneTimePreKeyId;
        this.oneTimePreKeyPublic = oneTimePreKeyPublic;
    }
}
