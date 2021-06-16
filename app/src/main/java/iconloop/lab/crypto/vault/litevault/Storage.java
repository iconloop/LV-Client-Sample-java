package iconloop.lab.crypto.vault.litevault;

import com.google.gson.JsonObject;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.jose.*;
import iconloop.lab.crypto.vault.litevault.messages.*;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Vector;

public class Storage {

    private final String _id;
    private final ECKey _myKey;

    private final String _managerSignKeyId;
    private final ECKey _managerSignKey;
    private final String _managerKmKeyId;
    private final ECKey _managerKmKey;

    private final String _encAlgorithm;
    private final HashMap<String, ClientInfo> _clients;
    private final HashMap<String, String> _tokens;

    public Storage(String storageId, String encAlgorithm, ECKey kmKey, String manSignKeyId, JsonObject manSignKey, String manKmKeyId, JsonObject manKmKey) throws JoseException {
        _id = storageId;
        _myKey = kmKey;

        _encAlgorithm = encAlgorithm;

        _managerSignKey = ECKey.parse(manSignKey);
        _managerSignKeyId = manSignKeyId;
        _managerKmKey = ECKey.parse(manKmKey);
        _managerKmKeyId = manKmKeyId;

        _clients = new HashMap<String, ClientInfo>();
        _tokens = new HashMap<String, String>();
    }

    public String getStorageId() {
        return _id;
    }

    public JsonObject getStorageKmKey() {
        return _myKey.toJsonObject();
    }

    public TokenRequest checkTokenRequest(String jweTokenRequest) throws JoseException, LiteVaultException {
        TokenRequest tokenReq = TokenRequest.develop(jweTokenRequest, _myKey);

        // check managerSignKey
        String jwsVC = tokenReq.getVC();
        LVCredential vc = LVCredential.parse(jwsVC, _managerSignKeyId, _managerSignKey);

        // check publicKey(in VC) vs publicKey(in Header)
        JsonObject vcPubKey = vc.getClientKey();
        ECKey headerPubKey = tokenReq.getSenderKey();
        if(!headerPubKey.equals(ECKey.parse(vcPubKey)))
            throw new LiteVaultException("PublicKey check failed.");

        // check vc claims
        long exp = vc.getExp();
        if(exp < (System.currentTimeMillis()/1000))
            throw new LiteVaultException("expired credential");

        if(!checkVC(jwsVC))
            throw new LiteVaultException("Invalid credential");

        if(!checkMethods(vc.getAuthMethods()))
            throw new LiteVaultException("Unsupported auth method");

        // save
        String vaultId = vc.getVaultId();
        SecretKey sKey = tokenReq.getDerivedKey();
        ClientInfo client = _clients.get(vaultId);
        String token = makeToken(sKey);
        if(client == null) {
            client = new ClientInfo(vaultId);
        }
        client.setSecretKey(sKey);
        _clients.put(vaultId, client);
        _tokens.put(token, vaultId);

        tokenReq.setToken(token);
        return tokenReq;
    }

    public String makeTokenResponse(TokenRequest tokenRequest, long iat) throws JoseException {
        String token = tokenRequest.getToken();
        SecretKey sKey = tokenRequest.getDerivedKey();
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));

        TokenResponse tokenResp = new TokenResponse(iat, token);
        return tokenResp.envelop(_encAlgorithm, tokenRequest.getKeyId(), sKey);
    }

    public String processWrite(String jweWriteRequest, long iat) throws JoseException {
        String vaultId = null;
        String error = null;
        int seq = -1;
        String token = null;
        ClientInfo client = null;
        try {
            JweDecrypt jwd = JweDecrypt.parse(jweWriteRequest);
            token = jwd.getKid();
            vaultId = _tokens.get(token);
            client = _clients.get(vaultId);

System.out.println("   * cek           : " + Hex.toHexString(client.getSecretKey().getEncoded()));
            WriteRequest request = WriteRequest.develop(jweWriteRequest, client.getSecretKey());

            seq = request.getSequence();
            if(seq < client.getSequence()) {
                throw new LiteVaultException("sequence error(" + seq + ")");
            }
            client.setClue(seq, request.getData());
            _clients.put(vaultId, client);

        } catch (JoseException e) {
            error = e.getMessage();
        } catch (LiteVaultException e) {
            error = e.getMessage();
        }
System.out.println(" - Encrypt WriteResponse");
System.out.println("   * cek           : " + Hex.toHexString(client.getSecretKey().getEncoded()));
        WriteResponse writeResp = new WriteResponse(iat, vaultId, error, seq);
        return writeResp.envelop(_encAlgorithm, token, client.getSecretKey());
    }

    public String processRead(String jweReadRequest, long iat) throws JoseException {
        String token = null;
        String vaultId = null;
        String data = null;
        int seq = 0;
        String error = null;
        SecretKey sKey = null;
        try {
            JweDecrypt jwd = JweDecrypt.parse(jweReadRequest);
            token = jwd.getKid();
            vaultId = _tokens.get(token);
            if(vaultId == null)
                throw new LiteVaultException("Unknown token");

            ClientInfo client = _clients.get(vaultId);
            sKey = client.getSecretKey();
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));
            ReadRequest request = ReadRequest.develop(jweReadRequest, sKey);
            String reqVaultId = request.getVaultId();

            if(!vaultId.equals(reqVaultId))
                throw new LiteVaultException("illegal vaultId(" + reqVaultId + ")");

            data = client.getClue();
            seq = client.getSequence();
System.out.println("   * data          : " + data);
System.out.println("   * sequence      : " + seq);
        } catch (JoseException e) {
            error = e.getMessage();
        } catch (LiteVaultException e) {
            error = e.getMessage();
        }
System.out.println(" - Encrypt ReadResponse");
        ReadResponse readResp = new ReadResponse(iat, vaultId, data, seq, error);
        return readResp.envelop(JoseHeader.JWE_ALG_DIRECT, _encAlgorithm, token, sKey);
    }



    private String makeToken(SecretKey key) {
        byte[] digest = Utils.sha256Digest(key.getEncoded());
        return Utils.encodeToBase64UrlSafeString(digest);
    }

    public String makeKeyId(ECKey key) {
        byte[] point = key.getPublicKey().getEncoded();
        byte[] digest = Utils.sha256Digest(point);
        return Hex.toHexString(digest);
    }

    public boolean checkMethods(Vector<String> authMethods) {
        for(String method : authMethods) {
            if( !method.equals("email") && !method.equals("phone"))
                return false;
        }
        return true;
    }

    // to do
    public boolean checkVC(String jwsVC) {
        return true;
    }

    static class ClientInfo {

        private final String _vId;
        private SecretKey _sKey;
        private String _clue;
        private int _seq;

        ClientInfo(String vaultId) {
            _vId = vaultId;
            _seq = 0;
        }

        void setSecretKey(SecretKey sKey) {
            _sKey = sKey;
        }

        void setClue(int seq, String clue) {
            _seq = seq;
            _clue = clue;
        }

        String getVaultId() {
            return _vId;
        }

        SecretKey getSecretKey() {
            return _sKey;
        }

        String getClue() {
            return _clue;
        }

        int getSequence() {
            return _seq;
        }
    }
}
