package iconloop.lab.crypto.mpc.ecdsa;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCMessage;
import org.bouncycastle.util.encoders.Hex;

import java.util.Iterator;
import java.util.Vector;

public class PlayerKey {

    public static final String KEY_SHARING_ID = "keyId";
    public static final String CURVE_NAME = "crv";
    public static final String MY_INDEX = "index";
    public static final String OTHER_INDEXES = "others";
    public static final String THRESHOLD_NUM = "t";
    public static final String XI = "xi";
    public static final String UIG = "uiG";

    private final String _keyId;
    private final EC _curve;
    private int _myIndex = -1;
    private Vector<Integer> _indexes;
    private final int _T;

    private EC.Scalar _myUij;

    private EC.Scalar _xi;
    private EC.Point _uiG;

    public PlayerKey(String jsonPlayerKey) {
        JsonObject playerKey = (JsonObject) JsonParser.parseString(jsonPlayerKey);
        String curveName = playerKey.get(CURVE_NAME).getAsString();
        String myIndex = playerKey.get(MY_INDEX).getAsString();
        String t = playerKey.get(THRESHOLD_NUM).getAsString();
        String xi = playerKey.get(XI).getAsString();
        String uiG = playerKey.get(UIG).getAsString();
        JsonArray otherIndexes = playerKey.get(OTHER_INDEXES).getAsJsonArray();

        _keyId = playerKey.get(KEY_SHARING_ID).getAsString();
        _curve = new EC(curveName);
        _myIndex = Integer.parseInt(myIndex);
        _T = Integer.parseInt(t);

        _indexes = new Vector<Integer>();
        for (Iterator<JsonElement> it = otherIndexes.iterator(); it.hasNext(); ) {
            JsonElement element = it.next();
            _indexes.add(element.getAsInt());
        }

        _xi = _curve.scalar(Hex.decode(xi));
        _uiG = _curve.point(Hex.decode(uiG));
    }

    public PlayerKey(String keySharingId, String curveName, int thresholdNum) {
        _keyId = keySharingId;
        _curve = new EC(curveName);
        _T = thresholdNum;
    }

    public void setIndex(int myIndex, int[] otherIndexes) throws MPCEcdsaException {
        if(_myIndex > 0)
            throw new MPCEcdsaException("MyIndex already been set.");

        if(_indexes != null && _indexes.size() > 0)
            throw new MPCEcdsaException("OtherIndex already been set.");

        _myIndex = myIndex;
        _indexes = new Vector<Integer>();
        for(int i : otherIndexes) {
            if(myIndex != i)
                _indexes.add(i);
        }
    }

    public String getKeyId() {
        return _keyId;
    }

    public EC getCurve() {
        return _curve;
    }

    public Vector<Integer> getOtherIndexes() {
        return _indexes;
    }

    public int getMyIndex() {
        return _myIndex;
    }

    public boolean hasMyIndex() {
        return (_myIndex > 0);
    }

    // Key Generation Phase2 i~iii
    public MPCMessage[] generateShare() {
        /* Generates (t+1)th random polynomial. */
        EC.Scalar[] coefs = new EC.Scalar[_T + 1];
        for (int i = 0; i < _T + 1; i++) {
            coefs[i] = _curve.getRandomScalar();
        }

        /** Additive-share of signing key, owned by Player_i.
         * "ui" is not used in this protocol. Don't store it.
         */
        _uiG = _curve.getBasePoint().scalarMul(coefs[0]);
        _xi = _curve.ScalarZero();

        MPCMessage[] priMsg = new MPCMessage[_indexes.size()];
        for(int i=0; i< priMsg.length; i++) {
            int index = _indexes.get(i);
            EC.Scalar uij = SecretSharing.f(_curve.scalar(index), coefs);
            priMsg[i] = new MPCMessage(_myIndex, index, MPCMessage.KS_UIJ, uij.toBytes());
        }
        _myUij = SecretSharing.f(_curve.scalar(_myIndex), coefs);

        return priMsg;
    }

    public MPCMessage[] updateShare() {
        /* Generates (t+1)th random polynomial. */
        EC.Scalar[] coefs = new EC.Scalar[_T + 1];
        coefs[0] = _curve.ScalarZero();
        for (int i = 1; i < _T + 1; i++) {
            coefs[i] = _curve.getRandomScalar();
        }

        MPCMessage[] priMsg = new MPCMessage[_indexes.size()];
        for(int i=0; i< priMsg.length; i++) {
            int index = _indexes.get(i);
            EC.Scalar uij = SecretSharing.f(_curve.scalar(index), coefs);
            priMsg[i] = new MPCMessage(_myIndex, index, MPCMessage.KS_UIJ, uij.toBytes());
        }
        _myUij = SecretSharing.f(_curve.scalar(_myIndex), coefs);

        return priMsg;
    }

    // Key Generation Phase2 iv
    public String doFinal(MPCMessage[] priMsg) {
        for( MPCMessage msg : priMsg) {
            EC.Scalar uij = _curve.scalar(msg.getData());
            _myUij = _myUij.add(uij);
        }

        _xi = _xi.add(_myUij);

        return _uiG.toString();
    }

    public EC.Scalar getWi(int[] signerIndex) {
        return SecretSharing.li(_curve, signerIndex, _myIndex).mul(_xi);
    }

    protected EC.Scalar getXi() {
        return _xi;
    }

    public String toString() {
        JsonObject obj = new JsonObject();
        obj.addProperty(KEY_SHARING_ID, _keyId);
        obj.addProperty(CURVE_NAME, _curve.getCurveName());
        obj.addProperty(THRESHOLD_NUM, _T + "");
        obj.addProperty(MY_INDEX, _myIndex + "");

        JsonArray others = new JsonArray();
        for(int index : _indexes)
            others.add(index + "");
        obj.add(OTHER_INDEXES, others);

        obj.addProperty(XI, _xi.toString());
        obj.addProperty(UIG, _uiG.toString());

        return obj.toString();
    }

}
