package iconloop.lab.crypto.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECDHUtils;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.io.IOException;

public class JweDecrypt {

    private final JoseHeader _header;
    private final byte[] _encryptedKey;
    private final byte[] _iv;
    private final byte[] _aad;
    private final byte[] _cipherText;
    private final byte[] _authTag;

    public JweDecrypt(JoseHeader header, byte[] encryptedKey, byte[] iv, byte[] cipherText, byte[] aad, byte[] authTag) {
        _header = header;
        _encryptedKey = encryptedKey;
        _iv = iv;
        _aad = aad;
        _cipherText = cipherText;
        _authTag = authTag;
    }

    public JoseHeader getHeader() throws JoseException {
        return _header;
    }

    public String getKid() {
        return _header.getKeyId();
    }

    public static JweDecrypt parse(String jweString) throws JoseException {
        String[] jwe = jweString.split("\\.");
        if (jwe.length != 5) {
            throw new JoseException("\"Unexpected number of Base64URL parts, must be five\"");
        }

        String strHeader = new String(Utils.decodeFromBase64UrlSafeString(jwe[0]));
        JsonObject jsonHeader = (JsonObject) JsonParser.parseString(strHeader);
        JoseHeader header = JoseHeader.parse(jsonHeader);
        byte[] aad = jwe[0].getBytes();
System.out.println("   * header        : " + strHeader);
        byte[] encryptedKey = null;
        if(jwe[1].length() > 1)
            encryptedKey = Utils.decodeFromBase64UrlSafeString(jwe[1]);

        byte[] iv = null;
        if(jwe[2].length() > 1)
            iv = Utils.decodeFromBase64UrlSafeString(jwe[2]);

        byte[] cipherText = null;
        if(jwe[3].length() > 1)
            cipherText = Utils.decodeFromBase64UrlSafeString(jwe[3]);

        byte[] authTag = null;
        if(jwe[4].length() > 1)
            authTag = Utils.decodeFromBase64UrlSafeString(jwe[4]);

        return new JweDecrypt(header, encryptedKey, iv, cipherText, aad, authTag);
    }

    public SecretKey deriveKey(ECKey decrypterKey, ECKey encrypterKey) throws JoseException {
        if(_header.getAlgorithm().equals(JoseHeader.JWE_ALG_DIRECT))
            throw new JoseException("this method does not support \"dir\" algorithm.");

        // derived secret
        ECKey otherKey = _header.getEphemeralKey();
        if(otherKey == null)
            otherKey = encrypterKey;

        SecretKey Z = null;
        try {
            Z = ECDHUtils.deriveSecret(decrypterKey.getCurveName(), JoseHeader.JWE_KDF_HASH, otherKey.getPublicKey(), decrypterKey.getPrivateKey());
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }
System.out.println("   * receivKey     : " + decrypterKey.toJsonObject());
System.out.println("   * senderKey     : " + otherKey.toJsonObject());
        // key encryption key(rfc7518#section-4.6.2)
        // In the Direct Key Agreement case,
        //      Data is set to the octets of the ASCII representation of the "enc" Header Parameter value.
        // In the Key Agreement with Key Wrapping case,
        //      Data is set to the octets of the ASCII representation of the "alg" (algorithm) Header Parameter value.
        String alg = _header.getAlgorithm();
        String keyWrapAlg = getKeyWrapAlgotirhm(alg);
        String encAlg = _header.getEncryptAlgorithm();
        String encKeyAlg = getJceEncAlgorithm(encAlg);

        String algorithmId = alg;
        if (alg.equals(JoseHeader.JWE_ALG_ECDH_ES))
            algorithmId = encAlg;
        int encKeyLength = getKeyLength(algorithmId);

        byte[] otherInfo = new byte[0];
        try {
            otherInfo = ECDHUtils.otherInfo(algorithmId, encKeyLength);
        } catch (IOException e) {
            throw new JoseException(e.getMessage());
        }

        // key encryption key
        SecretKey kek = null;
        try {
            kek = ECDHUtils.kdf(encKeyAlg, Z, encKeyLength, otherInfo);
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }
System.out.println("   * kek           : " + Hex.toHexString(kek.getEncoded()));
        if (keyWrapAlg == null) {
            return kek;
        } else {
            try {
                return ECDHUtils.keyUnWrapAES(encKeyAlg, _encryptedKey, kek);
            } catch (Exception e) {
                throw new JoseException(e.getMessage());
            }
        }
    }

    public byte[] decrypt(SecretKey cek) throws JoseException {
        String encAlg = _header.getEncryptAlgorithm();
        try {
            if(encAlg.equals(JoseHeader.JWE_ENC_A128GCM))
                return ECDHUtils.aesGcmDecrypt(_cipherText, cek, _iv, _aad, _authTag);
            else
                return null;
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }
    }

    private int getKeyLength(String algorithmId) throws JoseException {
        if(algorithmId.equals(JoseHeader.JWE_ALG_ECDH_ES_A128KW))
            return 128;
        else if(algorithmId.equals(JoseHeader.JWE_ENC_A128GCM))
            return 128;
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
