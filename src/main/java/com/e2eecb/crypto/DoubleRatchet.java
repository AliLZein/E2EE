package com.e2eecb.crypto;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class DoubleRatchet {

    public static class Header {
        public final X25519PublicKeyParameters dhPublic;
        public final int previousChainLength;
        public final int messageNumber;

        public Header(X25519PublicKeyParameters dhPublic, int previousChainLength, int messageNumber) {
            this.dhPublic = dhPublic;
            this.previousChainLength = previousChainLength;
            this.messageNumber = messageNumber;
        }

        public byte[] serialize() {
            byte[] dhEncoded = KeyUtils.encode(dhPublic);
            byte[] result = new byte[dhEncoded.length + 8];
            System.arraycopy(dhEncoded, 0, result, 0, dhEncoded.length);
            writeInt(result, dhEncoded.length, previousChainLength);
            writeInt(result, dhEncoded.length + 4, messageNumber);
            return result;
        }

        private static void writeInt(byte[] buffer, int offset, int value) {
            buffer[offset] = (byte) (value >>> 24);
            buffer[offset + 1] = (byte) (value >>> 16);
            buffer[offset + 2] = (byte) (value >>> 8);
            buffer[offset + 3] = (byte) value;
        }
    }

    public static class EncryptedMessage {
        public final Header header;
        public final byte[] ciphertext;

        public EncryptedMessage(Header header, byte[] ciphertext) {
            this.header = header;
            this.ciphertext = ciphertext;
        }
    }

    private X25519PrivateKeyParameters dhSelfPrivate;
    private X25519PublicKeyParameters dhSelfPublic;
    private X25519PublicKeyParameters dhRemotePublic;
    private byte[] rootKey;
    private byte[] sendingChainKey;
    private byte[] receivingChainKey;
    private int sendMessageNumber = 0;
    private int receiveMessageNumber = 0;
    private int previousSendingChainLength = 0;
    private final Map<String, byte[]> skippedMessageKeys = new HashMap<>();
    private static final int MAX_SKIP = 1000;

    public static DoubleRatchet initAsSender(byte[] sharedSecret, X25519PublicKeyParameters remotePublic) {
        DoubleRatchet ratchet = new DoubleRatchet();
        ratchet.dhSelfPrivate = KeyUtils.generateX25519PrivateKey();
        ratchet.dhSelfPublic = KeyUtils.derivePublic(ratchet.dhSelfPrivate);
        ratchet.dhRemotePublic = remotePublic;
        byte[] dhOutput = KeyUtils.agree(ratchet.dhSelfPrivate, remotePublic);
        byte[][] derived = kdfRootKey(sharedSecret, dhOutput);
        ratchet.rootKey = derived[0];
        ratchet.sendingChainKey = derived[1];
        return ratchet;
    }

    public static DoubleRatchet initAsReceiver(byte[] sharedSecret, X25519PrivateKeyParameters selfPrivate, X25519PublicKeyParameters selfPublic) {
        DoubleRatchet ratchet = new DoubleRatchet();
        ratchet.dhSelfPrivate = selfPrivate;
        ratchet.dhSelfPublic = selfPublic;
        ratchet.rootKey = sharedSecret;
        return ratchet;
    }

    public EncryptedMessage encrypt(byte[] plaintext) {
        byte[][] derived = kdfChainKey(sendingChainKey);
        sendingChainKey = derived[0];
        byte[] messageKey = derived[1];
        Header header = new Header(dhSelfPublic, previousSendingChainLength, sendMessageNumber);
        sendMessageNumber++;
        byte[] ciphertext = AesGcm.encrypt(messageKey, plaintext, header.serialize());
        return new EncryptedMessage(header, ciphertext);
    }

    public byte[] decrypt(EncryptedMessage message) {
        String skippedKey = encodeKey(message.header.dhPublic) + ":" + message.header.messageNumber;
        if (skippedMessageKeys.containsKey(skippedKey)) {
            byte[] messageKey = skippedMessageKeys.remove(skippedKey);
            return AesGcm.decrypt(messageKey, message.ciphertext, message.header.serialize());
        }

        if (dhRemotePublic == null || !encodeKey(dhRemotePublic).equals(encodeKey(message.header.dhPublic))) {
            if (dhRemotePublic != null) {
                skipMessageKeys(message.header.previousChainLength);
            }
            dhRatchetStep(message.header.dhPublic);
        }

        skipMessageKeys(message.header.messageNumber);

        byte[][] derived = kdfChainKey(receivingChainKey);
        receivingChainKey = derived[0];
        byte[] messageKey = derived[1];
        receiveMessageNumber++;
        return AesGcm.decrypt(messageKey, message.ciphertext, message.header.serialize());
    }

    private void skipMessageKeys(int untilMessageNumber) {
        if (receivingChainKey == null) {
            return;
        }
        if (untilMessageNumber - receiveMessageNumber > MAX_SKIP) {
            throw new SecurityException("Too many skipped messages");
        }
        while (receiveMessageNumber < untilMessageNumber) {
            byte[][] derived = kdfChainKey(receivingChainKey);
            receivingChainKey = derived[0];
            byte[] messageKey = derived[1];
            String key = encodeKey(dhRemotePublic) + ":" + receiveMessageNumber;
            skippedMessageKeys.put(key, messageKey);
            receiveMessageNumber++;
        }
    }

    private void dhRatchetStep(X25519PublicKeyParameters newRemotePublic) {
        previousSendingChainLength = sendMessageNumber;
        sendMessageNumber = 0;
        receiveMessageNumber = 0;
        dhRemotePublic = newRemotePublic;

        byte[] dhOutput = KeyUtils.agree(dhSelfPrivate, dhRemotePublic);
        byte[][] derivedReceiving = kdfRootKey(rootKey, dhOutput);
        rootKey = derivedReceiving[0];
        receivingChainKey = derivedReceiving[1];

        dhSelfPrivate = KeyUtils.generateX25519PrivateKey();
        dhSelfPublic = KeyUtils.derivePublic(dhSelfPrivate);

        dhOutput = KeyUtils.agree(dhSelfPrivate, dhRemotePublic);
        byte[][] derivedSending = kdfRootKey(rootKey, dhOutput);
        rootKey = derivedSending[0];
        sendingChainKey = derivedSending[1];
    }

    private static byte[][] kdfRootKey(byte[] rootKey, byte[] dhOutput) {
        byte[] output = HKDF.derive(dhOutput, rootKey, "E2EECB-Ratchet".getBytes(), 64);
        byte[] newRootKey = new byte[32];
        byte[] chainKey = new byte[32];
        System.arraycopy(output, 0, newRootKey, 0, 32);
        System.arraycopy(output, 32, chainKey, 0, 32);
        return new byte[][]{newRootKey, chainKey};
    }

    private static byte[][] kdfChainKey(byte[] chainKey) {
        byte[] nextChainKey = hmac(chainKey, new byte[]{0x02});
        byte[] messageKey = hmac(chainKey, new byte[]{0x01});
        return new byte[][]{nextChainKey, messageKey};
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String encodeKey(X25519PublicKeyParameters key) {
        return Base64.getEncoder().encodeToString(KeyUtils.encode(key));
    }
}
