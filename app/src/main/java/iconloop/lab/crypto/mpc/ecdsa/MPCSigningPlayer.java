package iconloop.lab.crypto.mpc.ecdsa;

import iconloop.lab.crypto.he.paillier.PaillierException;
import iconloop.lab.crypto.he.paillier.PaillierPrivateKey;
import iconloop.lab.crypto.he.paillier.PaillierPublicKey;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCMessage;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCRepository;

import java.math.BigInteger;

public class MPCSigningPlayer {

    private final String _keyId;
    private final int _myIndex;
    private final Signer _signer;

    private MPCRepository _repo;

    public MPCSigningPlayer(PlayerKey playerKey, PaillierPrivateKey hePriKey) {
        _keyId = playerKey.getKeyId();
        _myIndex = playerKey.getMyIndex();

        _signer = new Signer(playerKey, hePriKey);
    }

    public String getKeyId() {
        return _keyId;
    }

    public int getIndex() {
        return _myIndex;
    }

    public void setRepository(String repositoryId) {
        _repo = MPCRepository.getInstance(repositoryId);
    }

    public void preSigningStep1() throws PaillierException {
        MPCMessage[] pre1 = _signer.preSignStep1();     // pre1[0] = encKi, pre1[1] = giG, pre1[2] = hePublicKey
        sendMessage(pre1);                              // broadcast
    }

    public void preSigningStep2(int[] signerIndex) throws PaillierException {
        Signer.PreSigningStep2Param[] param = new Signer.PreSigningStep2Param[signerIndex.length];
        for(int i=0; i<signerIndex.length; i++) {
            int index = signerIndex[i];

            MPCMessage msgEKi = readMessage(index, MPCMessage.BROADCAST, MPCMessage.PS_ENC_KI);
            BigInteger encKi = new BigInteger(1, msgEKi.getData());

            MPCMessage msgGiG = readMessage(index, MPCMessage.BROADCAST, MPCMessage.PS_GIG);
            byte[] giG = msgGiG.getData();

            MPCMessage msgPub = readMessage(index, MPCMessage.BROADCAST, MPCMessage.PS_HE_PUB_KEY);
            BigInteger n = new BigInteger(1, msgPub.getData());
            PaillierPublicKey pubKey = new PaillierPublicKey(n);

            param[i] = new Signer.PreSigningStep2Param(index, giG, encKi, pubKey);
        }

        MPCMessage[] pre2 = _signer.preSigningStep2(param);
        sendMessage(pre2);
    }

    public void preSigningStep3(int[] signerIndex) {
        Signer.PreSigningStep3Param[] param = new Signer.PreSigningStep3Param[signerIndex.length];
        for(int i=0; i< signerIndex.length; i++){
            int index = signerIndex[i];

            MPCMessage msgEKG = readMessage(index, _myIndex, MPCMessage.PS_ENC_KIGI);
            BigInteger encKiGi = new BigInteger(1, msgEKG.getData());

            MPCMessage msgEKW = readMessage(index, _myIndex, MPCMessage.PS_ENC_KIWI);
            BigInteger encKiWi = new BigInteger(1, msgEKW.getData());

            param[i] = new Signer.PreSigningStep3Param(encKiGi, encKiWi);
        }

        MPCMessage pre3 = _signer.preSigningStep3(param);
        sendMessage(new MPCMessage[]{pre3});
    }

    public byte[] preSigningStepFinal(int[] signerIndex) {
        Signer.PreSigningFinalParam[] param = new Signer.PreSigningFinalParam[signerIndex.length];
        for (int i = 0; i < signerIndex.length; i++) {
            int index = signerIndex[i];

            MPCMessage msgKgi = readMessage(index, MPCMessage.BROADCAST, MPCMessage.PS_KGI);
            param[i] = new Signer.PreSigningFinalParam(msgKgi.getData());
        }

        return _signer.preSigningFinal(param);
    }

    public byte[] sign(byte[] hashedMsg) {
        return _signer.partialSign(hashedMsg);
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
