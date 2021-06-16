package iconloop.lab.crypto.vault.litevault;

import com.google.gson.JsonObject;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.jose.ECKey;
import iconloop.lab.crypto.jose.JoseException;
import iconloop.lab.crypto.vault.SecretSharing;
import iconloop.lab.crypto.vault.litevault.messages.*;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.HashMap;

public class Client {

    private final String _myKeyId;
    private final ECKey _myKey;
    private final String _jweAlgorithm;
    private final String _encAlgorithm;

    // Manager Info
    private final String _managerSignKeyId;
    private final ECKey _managerSignKey;
    private final String _managerKmKeyId;
    private final ECKey _managerKmKey;
    private SecretKey _managerSecretKey;

    // Auth Response Info
    private String _vc;
    private String _vaultId;
    private SecretKey _recoveryKey;
    private HashMap<String, JsonObject> _storages;
    private HashMap<String, SecretKey> _storageSecKeys;
    private HashMap<String, String> _storageTokens;

    private int _seq = 0;


    public Client(String jweAlgorithm, String encAlgorithm, ECKey myKey, String managerSignKeyId, JsonObject managerSignKey, String managerKmKeyId, JsonObject managerKmKey) throws JoseException {
        _myKey = myKey;
        _myKeyId = makeKeyId(myKey);
        _jweAlgorithm = jweAlgorithm;
        _encAlgorithm = encAlgorithm;

        _managerSignKey = ECKey.parse(managerSignKey);
        _managerSignKeyId = managerSignKeyId;
        _managerKmKey = ECKey.parse(managerKmKey);
        _managerKmKeyId = managerKmKeyId;
    }

    public void setSequence(int seq) {
        _seq = seq;
    }

    public int getSequence() {
        return _seq;
    }

    public String makeAuthRequest(long iat) throws JoseException {
        AuthRequest authReq = new AuthRequest(iat, _myKey);
        String jwe = authReq.envelop(_jweAlgorithm, _encAlgorithm, _managerKmKeyId, _managerKmKey);
        _managerSecretKey = authReq.getDerivedKey();
        return jwe;
    }

    public void checkAuthResponse(String jweAuthResponse) throws JoseException, LiteVaultException {
System.out.println(" - Decrypt AuthResponse");
        AuthResponse authResp = AuthResponse.develop(jweAuthResponse, _managerKmKeyId, _managerSecretKey);

        // check managerSignKey
        String jwsVC = authResp.getVC();
        LVCredential cred = LVCredential.parse(jwsVC, _managerSignKeyId, _managerSignKey);
        if(cred != null) {
            _vaultId = cred.getVaultId();
            _vc = jwsVC;
            _recoveryKey = authResp.getRecoveriKey();
            _storages = authResp.getStorages();
System.out.println("   * VaultID       : " + _vaultId);
System.out.println("   * RecoveryKey   : " + Hex.toHexString(_recoveryKey.getEncoded()));
System.out.println("   * Storages(HMap): " + _storages);

        } else {
            throw new LiteVaultException("Signature validation failed.");
        }
    }

    public String makeTokenRequest(String storageId, ECKey storageKey, long iat) throws JoseException {
        TokenRequest tokenReq = new TokenRequest(iat, _vc, _myKey);
        String jwe = tokenReq.envelop(_jweAlgorithm, _encAlgorithm, storageId, storageKey);
        if(_storageSecKeys == null)
            _storageSecKeys = new HashMap<String, SecretKey>();
        _storageSecKeys.put(storageId, tokenReq.getDerivedKey());
        return jwe;
    }

    public void checkTokenResponse(String storageId, String jweTokenResponse) throws JoseException, LiteVaultException {
        SecretKey sKey = _storageSecKeys.get(storageId);
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));
        TokenResponse tokenResp = TokenResponse.develop(jweTokenResponse, storageId, sKey);

        if(_storageTokens == null)
            _storageTokens = new HashMap<String, String>();
        String token = tokenResp.getToken();
        _storageTokens.put(storageId, token);
System.out.println(" - Token           : " + token);
    }

    public String[] share(int N, int T, byte[] data) throws LiteVaultException {
        SecretSharing ss = new SecretSharing(new SecureRandom(), N, T);
        byte[][] clues = ss.split(data);
        String[] out = new String[N];
        for(int i=0; i<N; i++) {
            try {
                out[i] = encryptData(clues[i]);
            } catch (InvalidCipherTextException e) {
                throw new LiteVaultException("encrypt fail(" + e.getMessage() + ")");
            }
        }
        return out;
    }

    public byte[] reconstruct(int N, int T, String[] encClues) throws LiteVaultException {
        byte[][] shares = new byte[encClues.length][];
        for(int i=0; i< encClues.length; i++) {
            try {
                shares[i] = decryptData(encClues[i]);
            } catch (InvalidCipherTextException e) {
                throw new LiteVaultException("decrypt fail(" + e.getMessage() + ")");
            }
        }
        SecretSharing ss = new SecretSharing(new SecureRandom(), N, T);
        return ss.reconstruct(shares);
    }

    public String makeWriteRequest(String storageId, long iat, String encryptedClue) throws LiteVaultException {
        if(_recoveryKey == null)
            throw new LiteVaultException("no recovery key");

        try {
            String token = _storageTokens.get(storageId);
            SecretKey sKey = _storageSecKeys.get(storageId);
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));
            WriteRequest writeReq = new WriteRequest(iat, _vaultId, encryptedClue, _seq, token);
            return writeReq.envelop(_encAlgorithm, sKey);
        } catch (JoseException e) {
            throw new LiteVaultException("jwe fail(" + e.getMessage() + ")");
        }
    }

    public WriteResponse checkWriteResponse(String storageId, String jweWriteResponse) throws JoseException, LiteVaultException {
        String token = _storageTokens.get(storageId);
        SecretKey sKey = _storageSecKeys.get(storageId);

        return WriteResponse.develop(jweWriteResponse, token, sKey);
    }

    public String makeReadRequest(String storageId, long iat) throws JoseException {
        String token = _storageTokens.get(storageId);
        SecretKey sKey = _storageSecKeys.get(storageId);
System.out.println("   * cek           : " + Hex.toHexString(sKey.getEncoded()));
        ReadRequest readReq = new ReadRequest(iat, _vaultId, token);
        return readReq.envelop(_encAlgorithm, sKey);
    }

    public ReadResponse checkReadResponse(String storageId, String jweReadResponse) throws JoseException, LiteVaultException {
        String token = _storageTokens.get(storageId);
        SecretKey sKey = _storageSecKeys.get(storageId);

        return ReadResponse.develop(jweReadResponse, token, sKey);
    }

    public HashMap<String, JsonObject> getStorages() {
        return _storages;
    }

    public String makeKeyId(ECKey key) {
        byte[] point = key.getPublicKey().getEncoded();
        byte[] digest = Utils.sha256Digest(point);
        return Hex.toHexString(digest);
    }

    private String encryptData(byte[] data) throws InvalidCipherTextException {
        byte[] iv = Utils.getRandomBytes(16);
        byte[] cipherText = Utils.aesEncrypt(data, _recoveryKey, iv);
        byte[] output = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
        return Utils.encodeToBase64UrlSafeString(output);
    }

    private byte[] decryptData(String encrypted) throws InvalidCipherTextException {
        byte[] input = Utils.decodeFromBase64UrlSafeString(encrypted);
        byte[] iv = new byte[16];
        byte[] cipherText = new byte[input.length - iv.length];
        System.arraycopy(input, 0, iv, 0, iv.length);
        System.arraycopy(input, iv.length, cipherText, 0, cipherText.length);
        return Utils.aesDecrypt(cipherText, _recoveryKey, iv);
    }

}
