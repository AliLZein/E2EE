package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.io.ByteArrayOutputStream;

public class X3DH {

    public static class InitiationResult {
        public final byte[] sharedSecret;
        public final X25519PublicKeyParameters ephemeralPublic;
        public final Integer usedOneTimePreKeyId;

        public InitiationResult(byte[] sharedSecret, X25519PublicKeyParameters ephemeralPublic, Integer usedOneTimePreKeyId) {
            this.sharedSecret = sharedSecret;
            this.ephemeralPublic = ephemeralPublic;
            this.usedOneTimePreKeyId = usedOneTimePreKeyId;
        }
    }

    public static InitiationResult initiate(IdentityKeyPair initiatorIdentity, PreKeyBundle responderBundle) {
        if (!KeyUtils.verify(responderBundle.identitySigningPublic, KeyUtils.encode(responderBundle.signedPreKeyPublic), responderBundle.signedPreKeySignature)) {
            throw new SecurityException("Signed prekey signature invalid");
        }

        X25519PrivateKeyParameters ephemeralPrivate = KeyUtils.generateX25519PrivateKey();
        X25519PublicKeyParameters ephemeralPublic = KeyUtils.derivePublic(ephemeralPrivate);

        byte[] dh1 = KeyUtils.agree(initiatorIdentity.dhPrivate, responderBundle.signedPreKeyPublic);
        byte[] dh2 = KeyUtils.agree(ephemeralPrivate, responderBundle.identityDhPublic);
        byte[] dh3 = KeyUtils.agree(ephemeralPrivate, responderBundle.signedPreKeyPublic);

        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        writeAll(combined, dh1, dh2, dh3);

        Integer usedOneTimePreKeyId = null;
        if (responderBundle.oneTimePreKeyPublic != null) {
            byte[] dh4 = KeyUtils.agree(ephemeralPrivate, responderBundle.oneTimePreKeyPublic);
            writeAll(combined, dh4);
            usedOneTimePreKeyId = responderBundle.oneTimePreKeyId;
        }

        byte[] ikm = combined.toByteArray();
        byte[] sharedSecret = HKDF.derive(ikm, new byte[32], "E2EECB-X3DH".getBytes(), 32);
        return new InitiationResult(sharedSecret, ephemeralPublic, usedOneTimePreKeyId);
    }

    public static byte[] respond(IdentityKeyPair responderIdentity, SignedPreKey signedPreKey, OneTimePreKey usedOneTimePreKey,
                                  X25519PublicKeyParameters initiatorIdentityDhPublic, X25519PublicKeyParameters initiatorEphemeralPublic) {
        byte[] dh1 = KeyUtils.agree(signedPreKey.privateKey, initiatorIdentityDhPublic);
        byte[] dh2 = KeyUtils.agree(responderIdentity.dhPrivate, initiatorEphemeralPublic);
        byte[] dh3 = KeyUtils.agree(signedPreKey.privateKey, initiatorEphemeralPublic);

        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        writeAll(combined, dh1, dh2, dh3);

        if (usedOneTimePreKey != null) {
            byte[] dh4 = KeyUtils.agree(usedOneTimePreKey.privateKey, initiatorEphemeralPublic);
            writeAll(combined, dh4);
        }

        byte[] ikm = combined.toByteArray();
        return HKDF.derive(ikm, new byte[32], "E2EECB-X3DH".getBytes(), 32);
    }

    private static void writeAll(ByteArrayOutputStream out, byte[]... arrays) {
        try {
            for (byte[] array : arrays) {
                out.write(array);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
