package iconloop.lab.crypto.jose;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECUtils;

import java.math.BigInteger;

public class JwsVerify {

    private final JoseHeader _header;
    private final JsonObject _payload;
    private final byte[] _toBeSigined;
    private final String _b64Signature;

    public JwsVerify(JoseHeader header, JsonObject payload, byte[] toBeSigned, String b64Signature) throws JoseException {
        _header = header;
        _payload = payload;
        _toBeSigined = toBeSigned;
        _b64Signature = b64Signature;
    }

    public JoseHeader getHeader() throws JoseException {
        return _header;
    }

    public String getKid() {
        return _header.getKeyId();
    }

    public JsonObject getPayload(){
        return _payload;
    }

    public static JwsVerify parse(String jwsString) throws JoseException {
        String[] jws = jwsString.split("\\.");
        if (jws.length != 3) {
            if(jws.length != 2 || !jwsString.endsWith("."))
                throw new JoseException("Unexpected number of Base64URL parts, must be three");
        }

        String strHeader = new String(Utils.decodeFromBase64UrlSafeString(jws[0]));
        JsonObject jsonHeader = (JsonObject) JsonParser.parseString(strHeader);
        JoseHeader header = JoseHeader.parse(jsonHeader);

        int sigIndex = jwsString.lastIndexOf(".");
        String input = jwsString.substring(0, sigIndex);

        byte[] toBeSigned = null;
        if(header.getAlgorithm().equals(JoseHeader.JWS_ALG_ES256))
            toBeSigned = Utils.sha256Digest(input.getBytes());

        String strPayload = new String(Utils.decodeFromBase64UrlSafeString(jws[1]));
        JsonObject jsonPayload = (JsonObject) JsonParser.parseString(strPayload);

        String b64Signature = "";
        if(!header.getAlgorithm().equals(JoseHeader.JWS_ALG_NONE))
            b64Signature = jws[2];
        return new JwsVerify(header, jsonPayload, toBeSigned, b64Signature);
    }

    public boolean verify() throws JoseException {
        return verify(null);
    }

    public boolean verify(ECKey verKey) throws JoseException {
        String algorithm = _header.getAlgorithm();
        if(algorithm.equals(JoseHeader.JWS_ALG_NONE))
            return true;

        ECKey headerKey = _header.getJWK();
        if(headerKey != null && verKey != null)
            throw new JoseException("The verification key already exists in the header.");

        if(headerKey != null)
            verKey = headerKey;

        if(algorithm.equals(JoseHeader.JWS_ALG_ES256)) {
            BigInteger[] sig = decodeECDSASignature(_b64Signature);
            return ECUtils.verifyECDSA(_toBeSigined, verKey, sig[0], sig[1]);
        } else
            return false;
    }

    private BigInteger[] decodeECDSASignature(String b64Signature) throws JoseException {
        byte[] encodedSignValue = Utils.decodeFromBase64UrlSafeString(b64Signature);
        int rSize = 32;
        if(encodedSignValue.length != (32*2))
            throw new JoseException("Invalid signature encoding");

        byte[] rByte = new byte[rSize];
        byte[] sByte = new byte[rSize];
        System.arraycopy(encodedSignValue, 0, rByte, 0, rSize);
        System.arraycopy(encodedSignValue, rSize, sByte, 0, rSize);
        return new BigInteger[]{new BigInteger(1, rByte), new BigInteger(1, sByte)};
    }
}
