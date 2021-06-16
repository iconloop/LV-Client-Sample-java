package iconloop.lab.crypto.jose;

import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECDHUtils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.io.IOException;

public class JweEncrypt {

    private String _b64Header = null;
    private byte[] _encryptedKey = null;

    private final String _alg;
    private final String _enc;
    private final String _kid;

    public JweEncrypt(String algorithm, String encAlgorithm, String kid) {
        _alg = algorithm;
        _enc = encAlgorithm;
        _kid = kid;
    }

    public SecretKey deriveKey(ECKey otherKey, ECKey myKey, boolean setEpk) throws JoseException {
        if(_alg.equals(JoseHeader.JWE_ALG_DIRECT))
            throw new JoseException("this method does not support \"dir\" algorithm.");
System.out.println("   * senderKey     : " + myKey.toJsonObject());
System.out.println("   * receivKey     : " + otherKey.toJsonObject());
        // derived secret
        SecretKey Z = null;
        try {
            Z = ECDHUtils.deriveSecret(myKey.getCurveName(), JoseHeader.JWE_KDF_HASH, otherKey.getPublicKey(), myKey.getPrivateKey());
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }

        // key encryption key(rfc7518#section-4.6.2)
        // In the Direct Key Agreement case,
        //      Data is set to the octets of the ASCII representation of the "enc" Header Parameter value.
        // In the Key Agreement with Key Wrapping case,
        //      Data is set to the octets of the ASCII representation of the "alg" (algorithm) Header Parameter value.
        String alg = _alg;
        String keyWrapAlg = getKeyWrapAlgotirhm(alg);
        String encAlg = _enc;
        String encKeyAlg = getJceEncAlgorithm(encAlg);

        String algorithmId = alg;
        if (alg.equals(JoseHeader.JWE_ALG_ECDH_ES))
            algorithmId = encAlg;
        int encKeyLength = getKeyLength(algorithmId);

        byte[] otherInfo = new byte[0];
        try {
            otherInfo = ECDHUtils.otherInfo(algorithmId, encKeyLength * 8);
        } catch (IOException e) {
            throw new JoseException(e.getMessage());
        }

        // key encryption key
        SecretKey kek = null;
        try {
            kek = ECDHUtils.kdf(encKeyAlg, Z, encKeyLength * 8, otherInfo);
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }

        if(setEpk)
            _b64Header = makeHeader(myKey);
        else
            _b64Header = makeHeader(null);
        if (keyWrapAlg == null) {
            return kek;
        } else {
            try {
                SecretKey cek = Utils.generateSecretKey(encKeyAlg, encKeyLength);
System.out.println("   * kek           : " + Hex.toHexString(kek.getEncoded()));
System.out.println("   * cek           : " + Hex.toHexString(cek.getEncoded()));

                _encryptedKey = ECDHUtils.keyWrapAES(cek, kek);
                return cek;
            } catch (Exception e) {
                throw new JoseException(e.getMessage());
            }
        }
    }

    public String encrypt(byte[] payload, SecretKey cek) throws JoseException {
        // direct
        if(_b64Header == null)
            _b64Header = makeHeader(null);

        byte[] iv;
        byte[] cipherText;
        byte[] authTag;
        try {
            if(_enc.equals(JoseHeader.JWE_ENC_A128GCM)) {
                int ivLength = 12;
                int authTagLength = 16;
                iv = Utils.getRandomBytes(ivLength);
                byte[] encrypted = ECDHUtils.aesGcmEncrypt(payload, cek, iv, _b64Header.getBytes(), authTagLength * 8);

                cipherText = new byte[encrypted.length - authTagLength];
                System.arraycopy(encrypted, 0, cipherText, 0, cipherText.length);
                authTag = new byte[authTagLength];
                System.arraycopy(encrypted, cipherText.length, authTag, 0, authTagLength);
            } else
                return null;
        } catch (Exception e) {
            throw new JoseException(e);
        }

        String b64EncryptedKey = "";
        if(_encryptedKey != null)
            b64EncryptedKey = Utils.encodeToBase64UrlSafeString(_encryptedKey);
        String b64Iv = Utils.encodeToBase64UrlSafeString(iv);
        String b64CipherText = Utils.encodeToBase64UrlSafeString(cipherText);
        String b64AuthTag = Utils.encodeToBase64UrlSafeString(authTag);

        return _b64Header + "." + b64EncryptedKey + "." + b64Iv + "." + b64CipherText + "." + b64AuthTag;
    }

    private String makeHeader(ECKey myKey) {
        JoseHeader header = new JoseHeader(_alg, _kid, _enc, myKey);
        String strHeader = header.toString();
        return Utils.encodeToBase64UrlSafeString(strHeader.getBytes());
    }

    private int getKeyLength(String algorithmId) throws JoseException {
        if(algorithmId.equals(JoseHeader.JWE_ALG_ECDH_ES_A128KW))
            return 16;
        else if(algorithmId.equals(JoseHeader.JWE_ENC_A128GCM))
            return 16;
        else
            throw new JoseException("Unsupported AlgorithmID(" + algorithmId + ")");
    }

    private String getJceEncAlgorithm(String encAlgorithm) throws JoseException {
        if(encAlgorithm.equals(JoseHeader.JWE_ENC_A128GCM))
            return "AES";
        else
            throw new JoseException("Unsupported Encryption Algorithm(" + encAlgorithm + ")");
    }

    private String getKeyWrapAlgotirhm(String algorithm) throws JoseException {
        if (algorithm.equals(JoseHeader.JWE_ALG_ECDH_ES_A128KW))
            return "AESWrap";
        else if(algorithm.equals(JoseHeader.JWE_ALG_ECDH_ES))
            return null;
        else
            throw new JoseException("Unsupported KeyWrap Algorithm(" + algorithm + ")");
    }
}
