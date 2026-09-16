package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.util.HashMap;
import java.util.Map;

public class ChatUser {

    public final String userId;
    public final IdentityKeyPair identity;
    public final SignedPreKey signedPreKey;
    private final Map<Integer, OneTimePreKey> oneTimePreKeys = new HashMap<>();
    private final Map<String, DoubleRatchet> sessions = new HashMap<>();

    public ChatUser(String userId) {
        this.userId = userId;
        this.identity = new IdentityKeyPair();
        this.signedPreKey = new SignedPreKey(1, identity);
        for (int i = 1; i <= 10; i++) {
            OneTimePreKey opk = new OneTimePreKey(i);
            oneTimePreKeys.put(i, opk);
        }
    }

    public PreKeyBundle publishBundle() {
        Integer chosenId = oneTimePreKeys.keySet().stream().findFirst().orElse(null);
        X25519PublicKeyParameters opkPublic = chosenId != null ? oneTimePreKeys.get(chosenId).publicKey : null;
        return new PreKeyBundle(userId, identity.dhPublic, identity.signingPublic,
                signedPreKey.id, signedPreKey.publicKey, signedPreKey.signature,
                chosenId, opkPublic);
    }

    public InitialMessage startSession(String peerId, PreKeyBundle peerBundle, byte[] plaintext) {
        X3DH.InitiationResult result = X3DH.initiate(identity, peerBundle);
        DoubleRatchet ratchet = DoubleRatchet.initAsSender(result.sharedSecret, peerBundle.signedPreKeyPublic);
        sessions.put(peerId, ratchet);
        DoubleRatchet.EncryptedMessage firstMessage = ratchet.encrypt(plaintext);
        return new InitialMessage(identity.dhPublic, result.ephemeralPublic, result.usedOneTimePreKeyId, peerBundle.signedPreKeyId, firstMessage);
    }

    public byte[] acceptSession(String peerId, InitialMessage initialMessage) {
        OneTimePreKey usedOtp = initialMessage.usedOneTimePreKeyId != null ? oneTimePreKeys.remove(initialMessage.usedOneTimePreKeyId) : null;
        byte[] sharedSecret = X3DH.respond(identity, signedPreKey, usedOtp,
                initialMessage.initiatorIdentityDhPublic, initialMessage.initiatorEphemeralPublic);
        DoubleRatchet ratchet = DoubleRatchet.initAsReceiver(sharedSecret, signedPreKey.privateKey, signedPreKey.publicKey);
        byte[] plaintext = ratchet.decrypt(initialMessage.firstMessage);
        sessions.put(peerId, ratchet);
        return plaintext;
    }

    public DoubleRatchet.EncryptedMessage send(String peerId, byte[] plaintext) {
        DoubleRatchet ratchet = sessions.get(peerId);
        if (ratchet == null) {
            throw new IllegalStateException("No session with " + peerId);
        }
        return ratchet.encrypt(plaintext);
    }

    public byte[] receive(String peerId, DoubleRatchet.EncryptedMessage message) {
        DoubleRatchet ratchet = sessions.get(peerId);
        if (ratchet == null) {
            throw new IllegalStateException("No session with " + peerId);
        }
        return ratchet.decrypt(message);
    }
}
