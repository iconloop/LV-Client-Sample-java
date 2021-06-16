package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.*;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class AuthRequest {

    public static final String TYPE = "AUTH_REQUEST";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_PUBLICKEY = "publicKey";

    private final ECKey _kmKey;
    private final long _iat;
    private String _keyId;
    private SecretKey _sKey;

    public AuthRequest(long iat, ECKey senderKey) {
        _iat = iat;
        _kmKey = senderKey;
    }

    private AuthRequest(long iat, String keyId, ECKey senderKey, SecretKey sKey) {
        _iat = iat;
        _keyId = keyId;
        _kmKey = senderKey;
        _sKey = sKey;
    }

    public static AuthRequest develop(String jweAuthRequest, ECKey receiverKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweAuthRequest);

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

        JsonObject payloadPubKey = payload.get(Payload_PUBLICKEY).getAsJsonObject();
        if(!senderKey.equals(ECKey.parse(payloadPubKey)))
            throw new LiteVaultException("Header publicKey != Payload PublicKey");

        return new AuthRequest(iat, jwd.getKid(), senderKey, sKey);
    }

    public String envelop(String algorithm, String encAlgorithm, String kid,  ECKey receiverKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(algorithm, encAlgorithm, kid);
        _sKey = jwe.deriveKey(receiverKey, _kmKey, true);
        _keyId = kid;
System.out.println("   * payload       : " + getPayload());
        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, _sKey);
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.add(Payload_PUBLICKEY, _kmKey.toJsonObject());
        return payload;
    }

    public long getIat() {
        return _iat;
    }

    public JsonObject getSenderKey() {
        return _kmKey.toJsonObject();
    }

    public String getKeyId() {
        return _keyId;
    }

    public SecretKey getDerivedKey() {
        return _sKey;
    }

}
