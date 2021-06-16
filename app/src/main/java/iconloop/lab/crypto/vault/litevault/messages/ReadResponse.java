package iconloop.lab.crypto.vault.litevault.messages;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.jose.JweDecrypt;
import iconloop.lab.crypto.jose.JweEncrypt;

import javax.crypto.SecretKey;
import java.nio.charset.Charset;

public class ReadResponse {
    public static final String TYPE = "READ_RESPONSE";

    private static final String Payload_TYPE = "type";
    private static final String Payload_IAT = "iat";
    private static final String Payload_VID = "vID";
    private static final String Payload_DATA = "data";
    private static final String Payload_SEQ = "seq";
    private static final String Payload_ERR = "err";

    private final long _iat;
    private final String _vId;
    private final String _data;
    private final int _seq;
    private final String _err;

    public ReadResponse(long iat, String vaultId, String data, int seq, String error) {
        _iat = iat;
        _vId = vaultId;
        _data = data;
        _seq = seq;
        _err = error;
    }

    public long getIat() {
        return _iat;
    }

    public String getVaultId() {
        return _vId;
    }

    public String getData() {
        return _data;
    }

    public int getSequence() {
        return _seq;
    }

    public String getError() {
        return _err;
    }

    public String envelop(String algorithm, String encAlgorithm, String kid,  SecretKey sKey) throws JoseException {
        JweEncrypt jwe = new JweEncrypt(algorithm, encAlgorithm, kid);
System.out.println("   * payload       : " + getPayload());
        byte[] plainText = getPayload().toString().getBytes(Charset.forName("UTF-8"));
        return jwe.encrypt(plainText, sKey);
    }

    public static ReadResponse develop(String jweTokenResponse, String keyId, SecretKey sKey) throws JoseException, LiteVaultException {
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
        String vaultId = payload.get(Payload_VID).getAsString();
        String error = null;
        if(payload.has(Payload_ERR))
            throw new LiteVaultException("Resp Failed : " + payload.get(Payload_ERR).getAsString());

        String data = payload.get(Payload_DATA).getAsString();
        int seq = payload.get(Payload_SEQ).getAsInt();

        return new ReadResponse(iat, vaultId, data, seq, error);
    }

    public JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty(Payload_TYPE, TYPE);
        payload.addProperty(Payload_IAT, _iat);
        payload.addProperty(Payload_VID, _vId);
        payload.addProperty(Payload_DATA, _data);
        if(_err != null)
            payload.addProperty(Payload_ERR, _err);
        payload.addProperty(Payload_SEQ, _seq);
        return payload;
    }
}
