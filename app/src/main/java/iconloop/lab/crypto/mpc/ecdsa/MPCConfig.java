package iconloop.lab.crypto.mpc.ecdsa;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class MPCConfig {

    public static final String CURVE_NAME       = "crv";
    public static final String KEY_ID           = "keyId";
    public static final String NUMBER_PLAYER    = "n";
    public static final String NUMBER_THRESHOLD = "t";
    public static final String PUBLIC_KEY       = "pk";

    private final String _curveName;
    private final String _keyId;
    private final int _n;
    private final int _t;
    private String _publicKey;

    public MPCConfig(String keyId, String curveName, int n, int t) throws MPCEcdsaException {
        _keyId = keyId;
        _curveName = curveName;
        if( n < (t+1) )
            throw new MPCEcdsaException("The value t(" + t + ") MUST be in (0 < t < " + n + ").");

        _n = n;
        _t = t;
    }

    public MPCConfig(String jsonConfig) {
        JsonObject config = (JsonObject) JsonParser.parseString(jsonConfig);
        _keyId = config.get(KEY_ID).getAsString();
        _curveName = config.get(CURVE_NAME).getAsString();
        _n = config.get(NUMBER_PLAYER).getAsInt();
        _t = config.get(NUMBER_THRESHOLD).getAsInt();
        if(config.has(PUBLIC_KEY))
            _publicKey = config.get(PUBLIC_KEY).getAsString();
    }

    public String getCurveName() {
        return _curveName;
    }

    public String getKeyId() {
        return _keyId;
    }

    public int getNumberOfPlayers() {
        return _n;
    }

    public int getNumberOfThreshold() {
        return _t;
    }

    public void setPublicKey(String hexEncodedPoint) {
        _publicKey = hexEncodedPoint;
    }

    public String getEncodedPublicKey() {
        return _publicKey;
    }

    public String toString() {
        return toJsonObject().toString();
    }

    public JsonObject toJsonObject() {
        JsonObject object = new JsonObject();
        object.addProperty(KEY_ID, _keyId);
        object.addProperty(CURVE_NAME, _curveName);
        object.addProperty(NUMBER_PLAYER, _n);
        object.addProperty(NUMBER_THRESHOLD, _t);
        object.addProperty(PUBLIC_KEY, _publicKey);
        return object;
    }
}
