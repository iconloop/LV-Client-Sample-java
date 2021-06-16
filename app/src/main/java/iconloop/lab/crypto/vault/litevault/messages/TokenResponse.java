package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JoseHeader;
import iconloop.lab.crypto.jose.JweDecrypt;
import iconloop.lab.crypto.jose.JweEncrypt;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class TokenResponse {

    public static final String TYPE = "TOKEN_RESPONSE";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_TOKEN = "token";

    private final long _iat;
    private final String _token;

    public TokenResponse(long iat, String token) {
        _iat = iat;
        _token = token;
    }

    public long getIat() {
        return _iat;
    }

    public String getToken() {
        return _token;
    }

    public String envelop(String encAlgorithm, String kid,  SecretKey sKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(JoseHeader.JWE_ALG_DIRECT, encAlgorithm, kid);
System.out.println("   * payload       : " + getPayload());
        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, sKey);
    }

    public static TokenResponse develop(String jweTokenResponse, String keyId, SecretKey sKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweTokenResponse);
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
        String token = payload.get(Payload_TOKEN).getAsString();

        return new TokenResponse(iat, token);
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_TOKEN, _token);
        return payload;
    }
}
