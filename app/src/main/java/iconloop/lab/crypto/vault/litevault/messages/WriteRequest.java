package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JoseHeader;
import iconloop.lab.crypto.jose.JweDecrypt;
import iconloop.lab.crypto.jose.JweEncrypt;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class WriteRequest {

    public static final String TYPE = "WRITE_REQUEST";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_VID = "vID";
    private static final String Payload_DATA = "data";
    private static final String Payload_SEQ = "seq";

    private final long _iat;
    private final String _vID;
    private final String _data;
    private final int _seq;
    private final String _token;

    public WriteRequest(long iat, String vaultId, String data, int sequence, String token) {
        _iat = iat;
        _vID = vaultId;
        _data = data;
        _seq = sequence;
        _token = token;
    }

    public String envelop(String encAlgorithm, SecretKey sKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(JoseHeader.JWE_ALG_DIRECT, encAlgorithm, _token);
System.out.println("   * payload       : " + getPayload());
        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, sKey);
    }

    public static WriteRequest develop(String jweTokenRequest, SecretKey sKey) throws JoseException, LiteVaultException {
        JweDecrypt jwd = JweDecrypt.parse(jweTokenRequest);
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
        String data = payload.get(Payload_DATA).getAsString();
        int seq = payload.get(Payload_SEQ).getAsInt();

        return new WriteRequest(iat, vID, data, seq, token);
    }

    public String getVaultId() {
        return _vID;
    }

    public String getData() {
        return _data;
    }

    public int getSequence() {
        return _seq;
    }

    public String getToken() {
        return _token;
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_VID, _vID);
        payload.addProperty(Payload_DATA, _data);
        payload.addProperty(Payload_SEQ, _seq);
        return payload;
    }
}
