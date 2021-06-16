package iconloop.lab.crypto.mpc.ecdsa;

import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECUtils;
import iconloop.lab.crypto.he.paillier.PaillierException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.HashMap;

public class MPCClient {

    public static final int KEY_SHARING_MODE = 1;
    public static final int KEY_UPDATE_MODE  = 2;
    public static final int SIGNING_MODE     = 3;

    private final String _repoId;

    private int _mode = 0;
    private String _keyId;
    private String _curveName;
    private int _n = 0;
    private int _threshold = 0;

    private int _lastIndex;
    private HashMap<Integer, MPCKeySharingPlayer> _players;
    private HashMap<Integer, MPCSigningPlayer> _signers;
    private String _publicKey;


    public MPCClient(String repoId) {
        _repoId = repoId;
    }

    public void init(int mode, MPCConfig config) {
        _mode = mode;
        _keyId = config.getKeyId();
        _curveName = config.getCurveName();
        _n = config.getNumberOfPlayers();
        _threshold = config.getNumberOfThreshold();
        _publicKey = config.getEncodedPublicKey();
    }

    public int addKeySharingPlayer(MPCKeySharingPlayer player) throws MPCEcdsaException {
        if(_mode != KEY_SHARING_MODE)
            throw new MPCEcdsaException("object not initialized for key sharing.");

        if(_players == null)
            _players = new HashMap<Integer, MPCKeySharingPlayer>();

        int index = ++_lastIndex;
        _players.put(index, player);
        return index;
    }

    public int addKeyUpdatePlayer(MPCKeySharingPlayer player) throws MPCEcdsaException {
        if(_mode != KEY_UPDATE_MODE)
            throw new MPCEcdsaException("object not initialized for key update.");

        if(_players == null)
            _players = new HashMap<Integer, MPCKeySharingPlayer>();

        String keyId = player.getKeyId();
        if(!keyId.equals(_keyId))
            throw new MPCEcdsaException("Key ID(" + keyId + ") is not \"" + _keyId + "\"");

        int index = player.getIndex();
        _players.put(index, player);
        return index;
    }

    public int addSignPlayer(MPCSigningPlayer player) throws MPCEcdsaException {
        if(_mode != SIGNING_MODE)
            throw new MPCEcdsaException("object not initialized for signing.");

        if(_signers == null)
            _signers = new HashMap<Integer, MPCSigningPlayer>();

        String keyId = player.getKeyId();
        if(!keyId.equals(_keyId))
            throw new MPCEcdsaException("Key ID(" + keyId + ") is not \"" + _keyId + "\"");

        int index = player.getIndex();
        _signers.put(index, player);
        return index;
    }

    // return ECDSA Public Key(compressed EC.point)
    public String keySharing() throws MPCEcdsaException {
        if(_mode != KEY_SHARING_MODE)
            throw new MPCEcdsaException("object not initialized for key sharing.");

        if(_players.size() != _n)
            throw new MPCEcdsaException("The number of players required is " + _n + ", but only " + _players.size());

        int[] indexes = new int[_n];
        int k = 0;
        for( int index : _players.keySet() ){
            indexes[k++] = index;
        }

        for( int index : _players.keySet()) {
            MPCKeySharingPlayer player = _players.get(index);
            player.setIndex(index, indexes);
            player.setRepository(_repoId);
            player.generateKey();
        }

        MPCPublicKey publicKey = new MPCPublicKey(_curveName);
        for(int index : _players.keySet()) {
            MPCKeySharingPlayer player = _players.get(index);
            String uiG = player.doFinal();
            publicKey.addPartialPoint(Hex.decode(uiG));
        }

        return publicKey.toString();

    }

    public String keyUpdate() throws MPCEcdsaException {
        if(_mode != KEY_UPDATE_MODE)
            throw new MPCEcdsaException("object not initialized for key update.");

        if( _n != _players.size())
            throw new MPCEcdsaException("The defined value n(" + _n + ") and number of Players(" + _players.size() + ") are different.");

        for( int index : _players.keySet()) {
            MPCKeySharingPlayer player = _players.get(index);
            player.setRepository(_repoId);
            player.updateKey();
        }

        MPCPublicKey publicKey = new MPCPublicKey(_curveName);
        for(int index : _players.keySet()) {
            MPCKeySharingPlayer player = _players.get(index);
            String uiG = player.doFinal();
            publicKey.addPartialPoint(Hex.decode(uiG));
        }

        return publicKey.toString();
    }

    public String signing(byte[] message) throws MPCEcdsaException, PaillierException {
        if (_mode != SIGNING_MODE)
            throw new MPCEcdsaException("object not initialized for signing.");

        if ( _threshold > (_signers.size()-1))
            throw new MPCEcdsaException("number of signer(" + _signers.size() + ") must be greater than the defined value t(" + _threshold + ").");

        int[] indexes = new int[_signers.size()];
        int k = 0;
        for( int index : _signers.keySet() ){
            indexes[k++] = index;
        }

        for (int index : _signers.keySet()) {
            MPCSigningPlayer signer = _signers.get(index);
            signer.setRepository(_repoId);
            signer.preSigningStep1();

        }

        for( int index : _signers.keySet()) {
            MPCSigningPlayer signer = _signers.get(index);
            signer.preSigningStep2(indexes);
        }

        for( int index : _signers.keySet()) {
            MPCSigningPlayer signer = _signers.get(index);
            signer.preSigningStep3(indexes);
        }

        byte[] preSignedR = null;
        for( int index : _signers.keySet()) {
            MPCSigningPlayer signer = _signers.get(index);
            byte[] r = signer.preSigningStepFinal(indexes);
            if(preSignedR == null)
                preSignedR = r.clone();
            else {
                if(!Arrays.areEqual(r, preSignedR))
                    throw new MPCEcdsaException("Signature Fail.(" + Hex.toHexString(r) + " : " + Hex.toHexString(preSignedR) + ")");
            }
        }

        MPCSignature signature = new MPCSignature(_curveName, preSignedR);
        EC.Scalar s = new EC(_curveName).scalar(0);
        for(int index : _signers.keySet()) {
            MPCSigningPlayer signer = _signers.get(index);
            byte[] iS = signer.sign(message);
            signature.addPartialSign(iS);
        }

        return Hex.toHexString(signature.getSignature());
    }


    public String[] getPlayerKey() {
        String[] keys = new String[_players.size()];
        int i=0;
        for(int index : _players.keySet()) {
            MPCKeySharingPlayer player = _players.get(index);
            keys[i++] = player.getPlayerKey();
        }
        return keys;
    }

    public boolean checkKeyPair(String publicKey) {
        int t = _players.size();
        EC.Scalar[] fxi = new EC.Scalar[t];
        int[] xi = new int[t];

        int i=0;
        for(int index : _players.keySet()) {
            fxi[i] = _players.get(index).getXi();
            xi[i] = index;
            i++;
        }

        EC ec = new EC(_curveName);
        EC.Scalar s = SecretSharing.interpolate(ec, xi, fxi);

        EC.Point out = ec.getBasePoint().scalarMul(s);
        System.out.println("   - s     : " + s);
        System.out.println("   - pub   : " + publicKey);
        System.out.println("   - sG    : " + out.toString());
        return publicKey.equals(out.toString());
    }

    private static class MPCSignature {

        private EC _curve;
        private EC.Scalar _r;
        private EC.Scalar _s;

        private MPCSignature(String curveName, byte[] r) {
            _curve = new EC(curveName);
            _r = _curve.scalar(r);
            _s = _curve.scalar(0);
        }

        private void addPartialSign(byte[] s) {
            EC.Scalar iS = _curve.scalar(s);
            _s = _s.add(iS);
        }

        private byte[] getSignature() throws MPCEcdsaException {
            try {
                return ECUtils.encodeStdDSASignature(_r.getValue(), _s.getValue());
            } catch (IOException e) {
                throw new MPCEcdsaException(e);
            }
        }
    }

    private static class MPCPublicKey {

        private final EC _curve;
        private EC.Point _g;

        private MPCPublicKey(String curveName) {
            _curve = new EC(curveName);
            _g = _curve.getInfinity();
        }

        private void addPartialPoint(byte[] encodedPoint) {
            _g = _g.add(_curve.point(encodedPoint));
        }

        private byte[] getEncodedPoint(boolean compressed) {
            return _g.toBytes(compressed);
        }

        public String toString() {
            return Hex.toHexString(getEncodedPoint(true));
        }
    }

}
