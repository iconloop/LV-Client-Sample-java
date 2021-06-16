package iconloop.lab.crypto.mpc.ecdsa;

import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCMessage;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCRepository;

import java.util.Vector;

public class MPCKeySharingPlayer {

    private final String _keyId;
    private final PlayerKey _playerKey;

    private MPCRepository _repo;

    public MPCKeySharingPlayer(MPCConfig config) {
        _keyId = config.getKeyId();
        _playerKey = new PlayerKey(config.getKeyId(), config.getCurveName(), config.getNumberOfThreshold());
    }

    public MPCKeySharingPlayer(PlayerKey playerKey) {
        _keyId = playerKey.getKeyId();
        _playerKey = playerKey;
    }

    public String getKeyId() {
        return _keyId;
    }

    public int getIndex() {
        return _playerKey.getMyIndex();
    }

    public void setIndex(int myIndex, int[] playerIndexes) throws MPCEcdsaException {
        if(_playerKey.hasMyIndex())
            throw new MPCEcdsaException("Shared Key(MyIndex : " + _playerKey.getMyIndex() + ") already exist.");

        _playerKey.setIndex(myIndex, playerIndexes);
    }

    public void setRepository(String repoId) {
        _repo = MPCRepository.getInstance(repoId);
    }

    public void generateKey() throws MPCEcdsaException {
        if(_repo == null)
            throw new MPCEcdsaException(("Repository is null"));

        // make and share Uij
        MPCMessage[] messages = _playerKey.generateShare();
        sendMessage(messages);
    }

    public void updateKey() throws MPCEcdsaException {
        if(_repo == null)
            throw new MPCEcdsaException(("Repository is null"));

        // update and share Uij
        MPCMessage[] messages = _playerKey.updateShare();
        sendMessage(messages);
    }

    public String doFinal() {
        int myIndex = _playerKey.getMyIndex();
        Vector<Integer> indexes = _playerKey.getOtherIndexes();
        MPCMessage[] messages = new MPCMessage[indexes.size()];
        for(int i=0; i<indexes.size(); i++) {
            int index = indexes.get(i);
            messages[i] = readMessage(index, myIndex, MPCMessage.KS_UIJ);
        }

        return _playerKey.doFinal(messages);
    }

    protected EC.Scalar getXi() {
        return _playerKey.getXi();
    }

    protected String getPlayerKey() {
        return _playerKey.toString();
    }

    private MPCMessage readMessage(int from, int to, String type) {
        String message = _repo.readMessage(from, to, type);
        return new MPCMessage(message);
    }

    private void sendMessage(MPCMessage[] messages) {
        for( MPCMessage message : messages) {
            _repo.saveMessage(message.toString());
        }
    }
}
