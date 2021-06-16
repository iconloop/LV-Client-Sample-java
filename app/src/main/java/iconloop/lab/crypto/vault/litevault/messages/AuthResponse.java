package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.jose.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.HashMap;

public class AuthResponse {

    public static final String TYPE = "AUTH_RESPONSE";
    public static final String REC_ALGORITHM = "AES";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_VC = "vC";
    private static final String Payload_REC = "rec";
    private static final String Payload_STR = "storages";
    private static final String Payload_STR_ID = "id";
    private static final String Payload_STR_PUBKEY = "key";

    private final long _iat;
    private final String _vc;
    private final byte[] _rec;
    private final HashMap<String, JsonObject> _storages;

    public AuthResponse(long iat, String vc, byte[] recKey, HashMap<String, JsonObject> storages) {
        _iat = iat;
        _vc = vc;
        _rec = (byte[])recKey.clone();
        _storages = storages;
    }

    public long getIat() {
        return _iat;
    }

    public String getVC() {
        return _vc;
    }

    public SecretKey getRecoveriKey() {
        return new SecretKeySpec(_rec, REC_ALGORITHM);
    }

    public HashMap<String, JsonObject> getStorages() {
        return _storages;
    }

    public String envelop(String encAlgorithm, String kid,  SecretKey sKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(JoseHeader.JWE_ALG_DIRECT, encAlgorithm, kid);

        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, sKey);
    }

    public static AuthResponse develop(String jweAuthResponse, String keyId, SecretKey sKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweAuthResponse);
        String headerKid = jwd.getKid();
        if(!headerKid.equals(keyId))
            throw new LiteVaultException("Unknown key id(" + headerKid + ")");

        byte[] decrypted = jwd.decrypt(sKey);
        String strPayload = new String(decrypted, Charset.forName("UTF-8"));
System.out.println("   * dPayload      : " + strPayload);

        JsonObject payload = (JsonObject) JsonParser.parseString(strPayload);

        String type = payload.get(Payload_TYPE).getAsString();
        if(!type.equals(TYPE))
            throw new LiteVaultException("Not " + TYPE + " Type(" + type + ")");

        long iat = payload.get(Payload_IAT).getAsLong();
        String vc = payload.get(Payload_VC).getAsString();
        String b64Rec = payload.get(Payload_REC).getAsString();
        JsonArray storages = payload.getAsJsonArray(Payload_STR);
        HashMap<String, JsonObject> jsonStorages = new HashMap<String, JsonObject>();
        for(JsonElement storage : storages) {
            JsonObject obj = (JsonObject)storage;
            jsonStorages.put(obj.get(Payload_STR_ID).getAsString(), obj.get(Payload_STR_PUBKEY).getAsJsonObject());
        }
        return new AuthResponse(iat, vc, Utils.decodeFromBase64UrlSafeString(b64Rec), jsonStorages);
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_VC, _vc);
        if(_rec != null) {
            payload.addProperty(Payload_REC, Utils.encodeToBase64UrlSafeString(_rec));
        }
        JsonArray array = new JsonArray();
        for(String key : _storages.keySet()) {
            JsonObject obj = new JsonObject();
            obj.addProperty(Payload_STR_ID, key);
            obj.add(Payload_STR_PUBKEY, _storages.get(key));
            array.add(obj);
        }
        payload.add(Payload_STR, array);
        return payload;
    }

}
