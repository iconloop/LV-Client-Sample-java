package iconloop.lab.crypto.jose;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class JoseHeader {

    public static final String JOSE_HEADER_ALG = "alg";
    public static final String JOSE_HEADER_KID = "kid";
    public static final String JOSE_HEADER_ENC = "enc";
    public static final String JOSE_HEADER_EPK = "epk";
    public static final String JOSE_HEADER_JWK = "jwk";

    public static final String JWK_KEY_TYPE = "kty";
    public static final String JWK_CURVE_NAME = "crv";
    public static final String JWK_KEY_X = "x";
    public static final String JWK_KEY_Y = "y";
    public static final String JWK_KEY_D = "D";

    public static final String JWS_ALG_ES256          = "ES256";
    public static final String JWS_ALG_NONE           = "none";

    public static final String JWE_ALG_DIRECT         = "dir";
    public static final String JWE_ALG_ECDH_ES        = "ECDH-ES";
    public static final String JWE_ALG_ECDH_ES_A128KW = "ECDH-ES+A128KW";

    public static final String JWE_ENC_A128GCM        = "A128GCM";

    public static final String JWE_KDF_HASH           = "SHA-256";


    private final String _alg;
    private final String _kid;
    private final String _enc;
    private ECKey _jwk;
    private ECKey _epk;

    public JoseHeader(String algorithm, String kid) {
        this(algorithm, kid, null, null);
    }

    public JoseHeader(String algorithm, String kid, String enc, ECKey jwk) {
        _alg = algorithm;
        _kid = kid;
        if(isSigning(_alg))
            _jwk = jwk;
        else
            _epk = jwk;
        _enc = enc;
    }

    public static JoseHeader parse(JsonObject jsonHeader) throws JoseException {
        String algorithm = jsonHeader.get(JoseHeader.JOSE_HEADER_ALG).getAsString();
        String kid = jsonHeader.get(JoseHeader.JOSE_HEADER_KID).getAsString();
        String enc = null;
        ECKey jwk = null;
        JsonElement tmp = jsonHeader.get(JoseHeader.JOSE_HEADER_ENC);
        if(tmp != null)
            enc = tmp.getAsString();

        if(isSigning(algorithm)) {
            tmp = jsonHeader.get(JoseHeader.JOSE_HEADER_JWK);
            if(tmp != null)
                jwk = ECKey.parse(tmp.getAsJsonObject());
        } else {
            tmp = jsonHeader.get(JoseHeader.JOSE_HEADER_EPK);
            if(tmp != null)
                jwk = ECKey.parse(tmp.getAsJsonObject());
        }

        return new JoseHeader(algorithm, kid, enc, jwk);
    }

    private static boolean isSigning(String algorithm) {
        if(algorithm.equals(JoseHeader.JWS_ALG_ES256))
            return true;
        else
            return false;
    }

    public String getAlgorithm() {
        return _alg;
    }

    public String getKeyId() {
        return _kid;
    }

    public String getEncryptAlgorithm() {
        return _enc;
    }

    public ECKey getEphemeralKey() {
        return _epk;
    }

    public ECKey getJWK() {
        return _jwk;
    }

    public JsonObject toJsonObject() {
        JsonObject header = new JsonObject();
        header.addProperty(JoseHeader.JOSE_HEADER_ALG, _alg);
        if(_kid != null)
            header.addProperty(JoseHeader.JOSE_HEADER_KID, _kid);
        if(_jwk != null)
            header.add(JoseHeader.JOSE_HEADER_JWK, _jwk.toJsonObject());
        if(_epk != null)
            header.add(JoseHeader.JOSE_HEADER_EPK, _epk.toJsonObject());
        if(_enc != null)
            header.addProperty(JoseHeader.JOSE_HEADER_ENC, _enc);

        return header;
    }

    public String toString() {
        return toJsonObject().toString();
    }

}
