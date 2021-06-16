package iconloop.lab.crypto.ec.bouncycastle.curve;

import iconloop.lab.crypto.common.Utils;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RFC3394WrapEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ECDHUtils {

    private static final String ALGORITHM = "ECDH";

//    public static SecretKey deriveSecret(String encAlgorithm, ECPublicKey receiverPublic, ECPrivateKey senderPrivate) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
//        KeyAgreement agree = KeyAgreement.getInstance(ALGORITHM, PROVIDER);
//        agree.init(senderPrivate);
//        agree.doPhase(receiverPublic, true);
//        return new SecretKeySpec(agree.generateSecret(), encAlgorithm);
//    }

    public static SecretKey deriveSecret(String curveSpec, String encAlgorithm, BCECPublicKey receiverPublic, BCECPrivateKey senderPrivate) {
        EC ec = new EC(curveSpec);
        ECDomainParameters ecParams = ec.getDomainParameters();
        ECPrivateKeyParameters priParam = new ECPrivateKeyParameters(senderPrivate.getS(), ecParams);
        ECPublicKeyParameters pubParam = new ECPublicKeyParameters(receiverPublic.getQ(), ecParams);

        ECDHBasicAgreement agree = new ECDHBasicAgreement();
        agree.init(priParam);
        BigInteger secret = agree.calculateAgreement(pubParam);
        return new SecretKeySpec(Utils.bigIntToUnsigned(secret, (ec.getFieldSize()+7)/8), encAlgorithm);
    }

    public static byte[] otherInfo(String algorithmId, byte[] partyUInfo, byte[] partyVInfo, int keyLength) throws IOException {
        byte[] algId = encodeWithLength(algorithmId.getBytes());
        byte[] partyU = encodeWithLength(partyUInfo);
        byte[] partyV = encodeWithLength(partyVInfo);
        byte[] supPub = intToBytes(keyLength);
        byte[] supPri = null;

        return concatenate(algId, partyU, partyV, supPub, supPri);
    }

    public static byte[] otherInfo(String algorithmId, int keyLength) throws IOException {
        return otherInfo(algorithmId, new byte[0], new byte[0], keyLength);
    }

    public static SecretKey kdf(String encAlgorithm, SecretKey sharedSecret, int keyLength, byte[] otherInfo) {
        int hLen = 32; // with SHA-256

        byte[] hashBuf;
        int outputLen = 0;

        byte[] out = new byte[(keyLength + 7)/8];

        byte[] shared = sharedSecret.getEncoded();

        int round = (out.length + (hLen -1))/hLen;
        for(int i=1; i<=round; i++) {
            byte[] counter = intToBytes(i);

            hashBuf = Utils.sha256Digest(counter, shared, otherInfo);

            if(i == round)
                System.arraycopy(hashBuf, 0, out, outputLen, out.length - (i-1)*hLen);
            else
                System.arraycopy(hashBuf, 0, out, outputLen, hLen);
            outputLen += hLen;
        }
        return new SecretKeySpec(out, encAlgorithm);
    }

    public static byte[] encodeWithLength(byte[] data) throws IOException  {
        if(data == null)
            data = new byte[0];

        byte[] length = intToBytes(data.length);
        return concatenate(length, data);
    }

    public static byte[] intToBytes(int intValue) {
        byte[] res = new byte[4];
        res[0] = (byte) (intValue >>> 24);
        res[1] = (byte) ((intValue >>> 16));
        res[2] = (byte) ((intValue >>> 8));
        res[3] = (byte) (intValue & 0xFF);
        return res;
    }

    public static byte[] concatenate(byte[]... byteArrays) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (byte[] bytes : byteArrays) {

            if(bytes != null)
                baos.write(bytes);
        }
        return baos.toByteArray();
    }

    public static byte[] aesGcmDecrypt(byte[] cipherText, SecretKey cek, byte[] iv, byte[] aad, byte[] authTag) throws Exception {
        byte[] input = new byte[cipherText.length + authTag.length];
        System.arraycopy(cipherText, 0, input, 0, cipherText.length);
        System.arraycopy(authTag, 0, input, cipherText.length, authTag.length);

        KeyParameter keyParam = new KeyParameter(cek.getEncoded());
        AEADParameters param = new AEADParameters(keyParam, authTag.length * 8, iv);

        GCMBlockCipher decCipher = new GCMBlockCipher(new AESEngine());
        decCipher.init(false, param);

        decCipher.processAADBytes(aad, 0, aad.length);

        int outLeng = decCipher.getOutputSize(input.length);
        byte[] dec = new byte[outLeng];

        int len = decCipher.processBytes(input, 0, input.length, dec, 0);
        decCipher.doFinal(dec, len);

        return dec;
    }

    public static byte[] aesGcmEncrypt(byte[] plainText, SecretKey cek, byte[] iv, byte[] aad, int authTagLength) throws InvalidCipherTextException {
        KeyParameter keyParam = new KeyParameter(cek.getEncoded());
        AEADParameters param = new AEADParameters(keyParam, authTagLength, iv);

        GCMBlockCipher encCipher = new GCMBlockCipher(new AESEngine());
        encCipher.init(true, param);

        encCipher.processAADBytes(aad, 0, aad.length);

        int outLeng = encCipher.getOutputSize(plainText.length);
        byte[] enc = new byte[outLeng];

        int len = encCipher.processBytes(plainText, 0, plainText.length, enc, 0);
        encCipher.doFinal(enc, len);

        return enc;
    }

    public static byte[] keyWrapAES(SecretKey cek, SecretKey kek) {
        RFC3394WrapEngine cipher = new RFC3394WrapEngine(new AESEngine());
        cipher.init(true, new KeyParameter(kek.getEncoded()));
        byte[] in = cek.getEncoded();
        return cipher.wrap(in, 0, in.length);
    }

    public static SecretKey keyUnWrapAES(String algorithm, byte[] encryptedKey, SecretKey kek) throws InvalidCipherTextException {
        RFC3394WrapEngine cipher = new RFC3394WrapEngine(new AESEngine());
        cipher.init(false, new KeyParameter(kek.getEncoded()));
        byte[] dec = cipher.unwrap(encryptedKey, 0, encryptedKey.length);
        return new SecretKeySpec(dec, algorithm);
    }

}
