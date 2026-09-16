package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public class InitialMessage {

    public final X25519PublicKeyParameters initiatorIdentityDhPublic;
    public final X25519PublicKeyParameters initiatorEphemeralPublic;
    public final Integer usedOneTimePreKeyId;
    public final int usedSignedPreKeyId;
    public final DoubleRatchet.EncryptedMessage firstMessage;

    public InitialMessage(X25519PublicKeyParameters initiatorIdentityDhPublic, X25519PublicKeyParameters initiatorEphemeralPublic,
                           Integer usedOneTimePreKeyId, int usedSignedPreKeyId, DoubleRatchet.EncryptedMessage firstMessage) {
        this.initiatorIdentityDhPublic = initiatorIdentityDhPublic;
        this.initiatorEphemeralPublic = initiatorEphemeralPublic;
        this.usedOneTimePreKeyId = usedOneTimePreKeyId;
        this.usedSignedPreKeyId = usedSignedPreKeyId;
        this.firstMessage = firstMessage;
    }
}
