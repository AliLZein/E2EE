package com.e2eecb.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

public class HKDF {

    public static byte[] derive(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(inputKeyMaterial, salt, info));
        byte[] output = new byte[outputLength];
        generator.generateBytes(output, 0, outputLength);
        return output;
    }
}
