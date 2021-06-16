package iconloop.lab.crypto.common;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;

public class Utils {

    private static final SecureRandom _rng = new SecureRandom();

    public static byte[] sha256Digest(byte[] message) {
        SHA256Digest sha256 = new SHA256Digest();
        sha256.update(message, 0, message.length);
        byte[] output = new byte[sha256.getDigestSize()];
        sha256.doFinal(output, 0);
        return output;
    }

    public static byte[] sha256Digest(byte[]... messages) {
        SHA256Digest sha256 = new SHA256Digest();
        sha256.reset();
        byte[] output = new byte[sha256.getDigestSize()];
        for(byte[] message : messages) {
            sha256.update(message, 0, message.length);
        }
        sha256.doFinal(output, 0);
        return output;
    }

    public static byte[] sha3Digest(byte[]... messages) {
        SHA3Digest sha3 = new SHA3Digest(256);
        byte[] output = new byte[sha3.getDigestSize()];
        for(byte[] message : messages) {
            sha3.update(message, 0, message.length);
        }
        sha3.doFinal(output, 0);
        return output;
    }

    public static byte[] getRandomBytes(int byteLength) {
        byte[] rnd = new byte[byteLength];
        _rng.nextBytes(rnd);
        return rnd;
    }

    public static BigInteger getRandomInteger(int bitLength) {
        return new BigInteger(bitLength, _rng);
    }

    public static String encodeToBase64UrlSafeString(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    public static String encodeToBase64UrlSafeString(String data) {
        return encodeToBase64UrlSafeString(data.getBytes(Charset.forName("UTF-8")));
    }

    public static byte[] encodeToBase64UrlSafe(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encode(data);
    }

    public static byte[] encodeToBase64UrlSafe(String data) {
        return encodeToBase64UrlSafe(data.getBytes(Charset.forName("UTF-8")));
    }

    public static byte[] decodeFromBase64UrlSafeString(String b64Data) {
        return Base64.getUrlDecoder().decode(b64Data);
    }

    public static byte[] decodeFromBase64UrlSafe(byte[] b64Data) {
        return Base64.getUrlDecoder().decode(b64Data);
    }

    public static SecretKey generateSecretKey(String encMethod, int keyByteLength) {
        byte[] rnd = getRandomBytes(keyByteLength);
        return new SecretKeySpec(rnd, encMethod);
    }

    public static byte[] concat(byte[]... arrays) {
        int outLength = 0;
        for(byte[] array : arrays)
            outLength += array.length;

        byte[] out = new byte[outLength];
        int index = 0;
        for(byte[] array : arrays) {
            System.arraycopy(array, 0, out, index, array.length);
            index += array.length;
        }
        return out;
    }

    public static byte[] bigIntToUnsigned(BigInteger val, int outByteLength) {
        byte[] res = val.toByteArray();
        int index = 0;
        byte[] out = new byte[outByteLength];
        if (res[0] == 0) {
            index = 1;
        }
        int varLength = res.length - index;
        System.arraycopy(res, index, out, outByteLength - varLength, varLength);
        return out;
    }

    public static byte[] aesEncrypt(byte[] plainText, SecretKey sKey, byte[] iv) throws InvalidCipherTextException {
        KeyParameter keyParam = new KeyParameter(sKey.getEncoded());
        ParametersWithIV param = new ParametersWithIV(keyParam, iv);

        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        aes.init(true, param);
        byte[] output = new byte[aes.getOutputSize(plainText.length)];
        int ciphertextLength = aes.processBytes(plainText, 0, plainText.length, output, 0);
        ciphertextLength += aes.doFinal(output, ciphertextLength);

        byte[] result = new byte[ciphertextLength];
        System.arraycopy(output, 0, result, 0, ciphertextLength);

        return result;
    }

    public static byte[] aesDecrypt(byte[] cipherText, SecretKey sKey, byte[] iv) throws InvalidCipherTextException {
        KeyParameter keyParam = new KeyParameter(sKey.getEncoded());
        ParametersWithIV param = new ParametersWithIV(keyParam, iv);

        PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
        aes.init(false, param);
        byte[] output = new byte[aes.getOutputSize(cipherText.length)];
        int ciphertextLength = aes.processBytes(cipherText, 0, cipherText.length, output, 0);
        ciphertextLength += aes.doFinal(output, ciphertextLength);

        byte[] result = new byte[ciphertextLength];
        System.arraycopy(output, 0, result, 0, ciphertextLength);

        return result;
    }


}
