package com.e2eecb.crypto;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

public class KeyUtils {

    private static final SecureRandom RANDOM = new SecureRandom();

    public static X25519PrivateKeyParameters generateX25519PrivateKey() {
        return new X25519PrivateKeyParameters(RANDOM);
    }

    public static X25519PublicKeyParameters derivePublic(X25519PrivateKeyParameters privateKey) {
        return privateKey.generatePublicKey();
    }

    public static byte[] agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(publicKey, secret, 0);
        return secret;
    }

    public static Ed25519PrivateKeyParameters generateEd25519PrivateKey() {
        return new Ed25519PrivateKeyParameters(RANDOM);
    }

    public static Ed25519PublicKeyParameters derivePublic(Ed25519PrivateKeyParameters privateKey) {
        return privateKey.generatePublicKey();
    }

    public static byte[] sign(Ed25519PrivateKeyParameters privateKey, byte[] message) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    public static boolean verify(Ed25519PublicKeyParameters publicKey, byte[] message, byte[] signature) {
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, publicKey);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }

    public static byte[] encode(X25519PublicKeyParameters key) {
        return key.getEncoded();
    }

    public static X25519PublicKeyParameters decodeX25519Public(byte[] bytes) {
        return new X25519PublicKeyParameters(bytes, 0);
    }

    public static byte[] encode(Ed25519PublicKeyParameters key) {
        return key.getEncoded();
    }

    public static Ed25519PublicKeyParameters decodeEd25519Public(byte[] bytes) {
        return new Ed25519PublicKeyParameters(bytes, 0);
    }

    public static byte[] randomBytes(int length) {
        byte[] out = new byte[length];
        RANDOM.nextBytes(out);
        return out;
    }
}
