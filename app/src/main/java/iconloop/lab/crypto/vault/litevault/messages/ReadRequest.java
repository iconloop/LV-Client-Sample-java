package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JoseHeader;
import iconloop.lab.crypto.jose.JweDecrypt;
import iconloop.lab.crypto.jose.JweEncrypt;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class ReadRequest {

    public static final String TYPE = "READ_REQUEST";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_VID = "vID";

    private final long _iat;
    private final String _vID;
    private final String _token;

    public ReadRequest(long iat, String vaultId, String token) {
        _iat = iat;
        _vID = vaultId;
        _token = token;
    }

    public String envelop(String encAlgorithm, SecretKey sKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(JoseHeader.JWE_ALG_DIRECT, encAlgorithm, _token);
System.out.println("   * payload       : " + getPayload());
        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, sKey);
    }

    public static ReadRequest develop(String jweReadRequest, SecretKey sKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweReadRequest);
        String token = jwd.getKid();

        byte[] decrypted = jwd.decrypt(sKey);
        String strPayload = new String(decrypted, Charset.forName("UTF-8"));
System.out.println("   * dPayload      : " + strPayload);

        JsonObject payload = (JsonObject) JsonParser.parseString(strPayload);

        String type = payload.get(Payload_TYPE).getAsString();
        if(!type.equals(TYPE))
            throw new LiteVaultException("Not " + TYPE + " Type(" + type + ")");

        long iat = payload.get(Payload_IAT).getAsLong();
        String vID = payload.get(Payload_VID).getAsString();

        return new ReadRequest(iat, vID, token);
    }

    public String getVaultId() {
        return _vID;
    }

    public String getToken() {
        return _token;
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_VID, _vID);
        return payload;
    }
}
