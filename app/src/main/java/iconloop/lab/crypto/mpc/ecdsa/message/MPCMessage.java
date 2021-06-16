package iconloop.lab.crypto.mpc.ecdsa.message;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.util.encoders.Hex;

public class MPCMessage {

    public static final String KS_UIJ        = "uij";
    public static final String PS_HE_PUB_KEY = "hePubKey";
    public static final String PS_ENC_KI     = "encki";
    public static final String PS_GIG        = "giG";
    public static final String PS_ENC_KIGI   = "encKiGi";
    public static final String PS_ENC_KIWI   = "encKiWi";
    public static final String PS_KGI        = "kgi";

    public static final int BROADCAST = 0;

    private int _from = -1;
    private int _to = -1;
    private final String _type;
    private final byte[] _data;

    public MPCMessage(int from, int to, String type, byte[] data) {
        _from = from;
        _to = to;
        _type = type;
        _data = data;
    }

    public MPCMessage(String jsonMessage) {
        JsonObject msg = (JsonObject) JsonParser.parseString(jsonMessage);
        _from = msg.get(MPCRepository.FROM).getAsInt();
        _to = msg.get(MPCRepository.TO).getAsInt();
        _type = msg.get(MPCRepository.TYPE).getAsString();
        String hexData = msg.get(MPCRepository.DATA).getAsString();
        _data = Hex.decode(hexData);
    }

    public int getFrom() {
        return _from;
    }

    public int getTo() {
        return _to;
    }

    public String getType() {
        return _type;
    }

    public byte[] getData() {
        return _data;
    }


    public String toString() {
        return toJsonObject().toString();
    }

    public JsonObject toJsonObject() {
        JsonObject obj = new JsonObject();
        obj.addProperty(MPCRepository.FROM, _from);
        obj.addProperty(MPCRepository.TO, _to);
        obj.addProperty(MPCRepository.TYPE, _type);
        String hexData = Hex.toHexString(_data);
        obj.addProperty(MPCRepository.DATA, hexData);
        return obj;
    }
}
