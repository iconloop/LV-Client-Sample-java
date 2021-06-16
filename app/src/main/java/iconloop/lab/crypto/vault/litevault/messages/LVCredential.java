package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import iconloop.lab.crypto.jose.ECKey;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JwsSign;
import iconloop.lab.crypto.jose.JwsVerify;

import java.util.Vector;

public class LVCredential {

    public static final String TYPE = "CREDENTIAL";

    private static final String Payload_TYPE = "type";
    private static final String Payload_VID = "vID";
    private static final String Payload_IAT = "iat";
    private static final String Payload_EXP = "exp";
    private static final String Payload_AUTH = "auth";
    private static final String Payload_PUBLICKEY = "publicKey";

    private final long _iat;
    private final long _exp;
    private final String _vaultId;
    private final JsonObject _clientKey;
    private final Vector<String> _authMethods;

    public LVCredential(long iat, long exp, String vaultID, Vector<String> authMethods, JsonObject clientKey) {
        _iat = iat;
        _exp = exp;
        _vaultId = vaultID;
        _authMethods = authMethods;
        _clientKey = clientKey;
    }

    public static LVCredential parse(String jwsCredential, String verifyKeyId, ECKey verifyKey) throws JoseException, LiteVaultException {
        JwsVerify jwv = JwsVerify.parse(jwsCredential);
        if(jwv.verify(verifyKey)) {
            String headerKid = jwv.getHeader().getKeyId();
            if(!headerKid.equals(verifyKeyId))
                throw new LiteVaultException("Known key id(" + headerKid + ")");

            JsonObject payload = jwv.getPayload();
            long iat = payload.get(Payload_IAT).getAsLong();
            long exp = payload.get(Payload_EXP).getAsLong();
            String vaultId = payload.get(Payload_VID).getAsString();
            JsonArray jsonAuth = payload.getAsJsonArray(Payload_AUTH);
            Vector<String> authMethods = new Vector<String>();
            for(JsonElement methods : jsonAuth)
                authMethods.add(methods.getAsString());
            JsonObject clientKey = payload.getAsJsonObject(Payload_PUBLICKEY);
            return new LVCredential(iat, exp, vaultId, authMethods, clientKey);
        } else
            throw new LiteVaultException("Signature validation failed.");
    }

    public long getIat() {
        return _iat;
    }

    public long getExp() {
        return _exp;
    }

    public String getVaultId() {
        return _vaultId;
    }

    public Vector<String> getAuthMethods() {
        return _authMethods;
    }

    public JsonObject getClientKey() {
        return _clientKey;
    }

    public String makeCredential(String signAlgorithm, String sigerKid, ECKey signerKey) {
        JwsSign jws = new JwsSign(signAlgorithm, sigerKid);
        JsonObject payload = makePayload();
        return jws.sign(payload, signerKey, false);
    }

    private JsonObject makePayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_VID, _vaultId);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_EXP, _exp);
        if(_authMethods != null) {
            JsonArray array = new JsonArray();
            for (String authMethod : _authMethods)
                array.add(authMethod);
            payload.add(Payload_AUTH, array);
        }
        payload.add(Payload_PUBLICKEY, _clientKey);
        return payload;
    }
}
