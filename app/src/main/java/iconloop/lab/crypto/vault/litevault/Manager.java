package iconloop.lab.crypto.vault.litevault;

import com.google.gson.JsonObject;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECUtils;
import iconloop.lab.crypto.jose.ECKey;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.vault.litevault.messages.AuthRequest;
import iconloop.lab.crypto.vault.litevault.messages.AuthResponse;
import iconloop.lab.crypto.vault.litevault.messages.LVCredential;
import iconloop.lab.crypto.vault.litevault.messages.LiteVaultException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.util.HashMap;
import java.util.Vector;

public class Manager {

    private final String _signKeyId;
    private final ECKey _signKey;
    private final String _kmKeyId;
    private final ECKey _kmKey;

    private final String _encAlgorithm;

    private HashMap<String, JsonObject> _storages;
    private HashMap<String, ClientInfo> _clients;

    public Manager(String encAlgorithm, String signKeyId, ECKey signKey, String kmKeyId, ECKey kmKey) {
        _signKeyId = signKeyId;
        _signKey = signKey;

        _kmKeyId = kmKeyId;
        _kmKey = kmKey;

        _encAlgorithm = encAlgorithm;
        _storages = new HashMap<String, JsonObject>();
    }

    public String getSignKeyId() {
        return _signKeyId;
    }

    public JsonObject getSignKey() {
        return _signKey.toJsonObject();
    }

    public String getKmKeyId() {
        return _kmKeyId;
    }

    public JsonObject getKmKey() {
        return _kmKey.toJsonObject();
    }
    public void addStorage(String storageId,  JsonObject jwkObject) throws JoseException {
        _storages.put(storageId, jwkObject);
    }

    public JsonObject getStorageKmKey(String storageId) {
        return _storages.get(storageId);
    }

    public HashMap<String, JsonObject> getStorages() {
        return _storages;
    }

    public AuthRequest checkAuthRequest(String jweAuthRequest) throws JoseException, LiteVaultException {
        return AuthRequest.develop(jweAuthRequest, _kmKey);
    }

    public String clientAuth(String emailAddress, String phoneNumber) {
        String vaultId = makeVaultId(emailAddress, phoneNumber);
System.out.println("   * Vault ID      : " + vaultId);
        if(_clients == null)
            _clients = new HashMap<String, ClientInfo>();

        ClientInfo client = _clients.get(vaultId);
        if(client == null) {
            byte[] recKey = Utils.getRandomBytes(16);
            client = new ClientInfo(vaultId, recKey);
        }
        client.addAuthMethod("email");
        client.addAuthMethod("phone");

        _clients.put(vaultId, client);
        return vaultId;
    }

    public String makeCredential(String signAlgorithm, String vaultId, long iat, long exp, AuthRequest authRequest) {
        ClientInfo client = _clients.get(vaultId);

        LVCredential credential = new LVCredential(iat, exp, vaultId, client.getAuthMethods(), authRequest.getSenderKey());
        String vc = credential.makeCredential(signAlgorithm, _signKeyId, _signKey);

        client.setVc(vc);
        _clients.put(vaultId, client);

        return vc;
    }

    public String makeAuthResponse(AuthRequest authReq, long iat, String vaultId,  String jwsCredential) throws LiteVaultException, JoseException {
        ClientInfo client = _clients.get(vaultId);
        AuthResponse authResp = new AuthResponse(iat, jwsCredential, client.getRecoveryKey(), _storages);
        return authResp.envelop(_encAlgorithm, authReq.getKeyId(), authReq.getDerivedKey());
    }

    private String makeVaultId(String email, String phone) {
        byte[] seed = ECUtils.toUnsignedBytesFromBCECPrivateKey(_signKey.getPrivateKey());
System.out.println("   * seed          : " + Hex.toHexString(seed));
        byte[] vaultId = Utils.sha256Digest(email.getBytes(), phone.getBytes(), seed);
        return Utils.encodeToBase64UrlSafeString(vaultId);
    }

    static class ClientInfo {

        private String _vId;
        private byte[] _vc;
        private byte[] _recKey;
        private Vector<String> _authMethods;

        ClientInfo(String vId, byte[] recKey) {
            _vId = vId;
            _recKey = (byte[])recKey.clone();

            _authMethods = new Vector<String>();
        }

        String getVaultId() {
            return _vId;
        }

        byte[] getRecoveryKey() {
            return (byte[])_recKey.clone();
        }

        void addAuthMethod(String authMethod) {
            _authMethods.add(authMethod);
        }

        Vector<String> getAuthMethods() {
            return _authMethods;
        }

        void setVc(String jwsCredential) {
            _vc = Utils.sha256Digest(jwsCredential.getBytes());
        }

        boolean checkVC(byte[] hash) {
            return Arrays.areEqual(_vc, hash);
        }
    }

}
