package iconloop.lab.crypto.mpc.ecdsa.message;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashMap;
import java.util.Map;

public class MPCRepository {

    public static final String FROM = "from";
    public static final String TO   = "to";
    public static final String TYPE = "type";
    public static final String DATA = "data";

    private String _repoId;
    private static HashMap<String, MPCRepository> _repos;

    private Map<String, String> _data;

    private MPCRepository(String repoId) {
        _repoId = repoId;

        _data = new HashMap();
    }

    public static MPCRepository getInstance(String repoId) {
        if(_repos != null) {
            MPCRepository repo = _repos.get(repoId);
            if (repo != null) {
                return repo;
            }
        }

        _repos = new HashMap();
        MPCRepository repo = new MPCRepository(repoId);
        _repos.put(repoId, repo);
        return repo;
    }

    public void saveMessage(String jsonMessage) {
//System.out.println("### W : " + jsonMessage);
        JsonObject msg = (JsonObject)JsonParser.parseString(jsonMessage);
        int from = msg.get(FROM).getAsInt();
        JsonElement tmp =msg.get(TO);
        int to = 0;
        if(tmp != null)
            to = tmp.getAsInt();

        String type = msg.get(TYPE).getAsString();

        String key = getIndexKey(from, to, type);
        String data = msg.get(DATA).getAsString();
        _data.put(key, data);
    }

    public String readMessage(int from, int to, String type) {
        String key = getIndexKey(from, to, type);
        String data = _data.get(key);

        JsonObject obj = new JsonObject();
        obj.addProperty(FROM, from);
        obj.addProperty(TO, to);
        obj.addProperty(TYPE, type);
        obj.addProperty(DATA, data);
//System.out.println("### R : " + obj);
        return obj.toString();
    }

    private String getIndexKey(int from, int to, String method) {
        long il = ((long)from)<<32;
        il = il + to;
        String ils = Long.toHexString(il);

        return ils + method;
    }


}
