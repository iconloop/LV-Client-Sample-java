package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.ECKey;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JweDecrypt;
import iconloop.lab.crypto.jose.JweEncrypt;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class TokenRequest {

    public static final String TYPE = "TOKEN_REQUEST";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_VC = "vC";

    private final ECKey _kmKey;
    private final long _iat;
    private final String _vc;
    private String _keyId;
    private SecretKey _sKey;

    private String _token;

    public TokenRequest(long iat, String jwsCredential, ECKey senderKey) {
        _iat = iat;
        _vc = jwsCredential;
        _kmKey = senderKey;
    }

    private TokenRequest(long iat, String jwsCredential, String keyId, ECKey senderKey, SecretKey sKey) {
        _iat = iat;
        _vc = jwsCredential;
        _keyId = keyId;
        _kmKey = senderKey;
        _sKey = sKey;
    }

    public void setToken(String token) {
        _token = token;
    }

    public String getToken() {
        return _token;
    }

    public String envelop(String algorithm, String encAlgorithm, String kid,  ECKey receiverKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(algorithm, encAlgorithm, kid);
        _sKey = jwe.deriveKey(receiverKey, _kmKey, true);
        _keyId = kid;

        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, _sKey);
    }

    public static TokenRequest develop(String jweTokenRequest, ECKey receiverKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweTokenRequest);

        SecretKey sKey = jwd.deriveKey(receiverKey, null);
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));
        byte[] decrypted = jwd.decrypt(sKey);
        String strPayload = new String(decrypted, Charset.forName("UTF-8"));
System.out.println("   * dPayload      : " + strPayload);

        JsonObject payload = (JsonObject) JsonParser.parseString(strPayload);

        String type = payload.get(Payload_TYPE).getAsString();
        if(!type.equals(TYPE))
            throw new LiteVaultException("Not " + TYPE + " Type(" + type + ")");

        long iat = payload.get(Payload_IAT).getAsLong();
        ECKey senderKey = jwd.getHeader().getEphemeralKey();
        String vc = payload.get(Payload_VC).getAsString();

        return new TokenRequest(iat, vc, jwd.getKid(), senderKey, sKey);
    }

    public SecretKey getDerivedKey() {
        return _sKey;
    }

    public String getVC() {
        return _vc;
    }

    public String getKeyId() {
        return _keyId;
    }

    public ECKey getSenderKey() {
        return _kmKey;
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_VC, _vc);
        return payload;
    }
}
