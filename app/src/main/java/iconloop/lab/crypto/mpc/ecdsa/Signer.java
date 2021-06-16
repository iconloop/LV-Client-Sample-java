package iconloop.lab.crypto.mpc.ecdsa;

import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.he.paillier.PaillierException;
import iconloop.lab.crypto.he.paillier.PaillierPrivateKey;
import iconloop.lab.crypto.he.paillier.PaillierPublicKey;
import iconloop.lab.crypto.he.paillier.PaillierUtils;
import iconloop.lab.crypto.mpc.ecdsa.message.MPCMessage;

import java.math.BigInteger;

public class Signer {

    private final EC _curve;
    private final PlayerKey _playerKey;
    private final PaillierPrivateKey _hePrivKey;
    private final PaillierPublicKey _hePubKey;
    private final int _myIndex;
    private int[] _signerIndex;

    private EC.Scalar _ki;
    private EC.Scalar _gi;
    private EC.Scalar _sumK;
    private EC.Scalar _sumW;
    private EC.Point _gG;

    private EC.Scalar _kgi;
    private EC.Scalar _kwi;

    private EC.Scalar _r;

    public Signer(PlayerKey playerKey, PaillierPrivateKey hePrivKey) {
        _playerKey = playerKey;
        _curve = _playerKey.getCurve();
        _hePrivKey = hePrivKey;
        _hePubKey = hePrivKey.getPublicKey();
        _myIndex = playerKey.getMyIndex();
    }

    public MPCMessage[] preSignStep1() throws PaillierException {
        /* Randomly selects additive-share ki of k. */
        _ki = _curve.getRandomScalar();
        BigInteger encKi = _hePubKey.encrypt(_ki.getValue());

        /* Randomly selects additive-share gi of g. */
        _gi = _curve.getRandomScalar();

        /* Ready to release (gi)G to signerSet. */
        EC.Point giG = _curve.getBasePoint().scalarMul(_gi);

        MPCMessage encKiMsg = new MPCMessage(_myIndex, MPCMessage.BROADCAST, MPCMessage.PS_ENC_KI, encKi.toByteArray());
        MPCMessage giGMsg   = new MPCMessage(_myIndex, MPCMessage.BROADCAST, MPCMessage.PS_GIG, giG.toBytes(true));
        MPCMessage hePubKey = new MPCMessage(_myIndex, MPCMessage.BROADCAST, MPCMessage.PS_HE_PUB_KEY, _hePubKey.getEncoded());
        return new MPCMessage[]{encKiMsg, giGMsg, hePubKey};
    }

    public MPCMessage[] preSigningStep2(PreSigningStep2Param[] params) throws PaillierException {
        int[] signerIndex = new int[params.length];
        for(int i=0; i< params.length; i++) {
            signerIndex[i] = params[i].getIndex();
        }

        /* Convertint shamir-share xi of signing key to additive-share, named wi.*/
        EC.Scalar wi = _playerKey.getWi(signerIndex);

        /* Accumulate shares. */
        _sumK = _curve.ScalarZero();
        _sumW = _curve.ScalarZero();

        _gG = _curve.getInfinity();

        MPCMessage[] msg = new MPCMessage[params.length * 2];
        for(int i=0; i< params.length; i++) {
            PreSigningStep2Param param = params[i];

            EC.Point giG = _curve.point(param.getEncodedGiG());
            _gG = _gG.add(giG);
            BigInteger encKi =  param.getEncKi();
            PaillierPublicKey encKey = param.getHePublicKey();

            // Ready enc(err1), enc(err2)
            EC.Scalar betaK = _curve.getRandomScalar();
            EC.Scalar betaW = _curve.getRandomScalar();

            BigInteger encBetaK = encKey.encrypt(betaK.getValue());
            BigInteger encBetaW = encKey.encrypt(betaW.getValue());

            /* Calculating enc(ki*gj+err1), enc(ki*wj+err2)*/
            BigInteger encKiGi = PaillierUtils.cipherScalarMul(_gi.getValue(), encKi, encKey);
            BigInteger encKiWi = PaillierUtils.cipherScalarMul(wi.getValue(), encKi, encKey);
            BigInteger alphaK = PaillierUtils.cipherAdd(encKiGi, encBetaK, encKey);
            BigInteger alphaW = PaillierUtils.cipherAdd(encKiWi, encBetaW, encKey);

            /* Storing errs used to generate msg. notice that the beta and v are negative sums of errs. */
            _sumK = _sumK.add(_curve.scalar(0).sub(betaK));
            _sumW = _sumW.add(_curve.scalar(0).sub(betaW));

            msg[2*i  ] = new MPCMessage(_myIndex, param.getIndex(), MPCMessage.PS_ENC_KIGI, alphaK.toByteArray());
            msg[2*i+1] = new MPCMessage(_myIndex, param.getIndex(), MPCMessage.PS_ENC_KIWI, alphaW.toByteArray());
        }
        return msg;
    }

    public MPCMessage preSigningStep3(PreSigningStep3Param[] params) {
        EC.Scalar delta = _curve.scalar(0);
        EC.Scalar sigma = _curve.scalar(0);

        for (int i=0; i< params.length; i++) {
            PreSigningStep3Param param = params[i];

            /* Parsing and decrypt message to get deltaj = ki*gj+err1 and sigmaj = ki*wj+err2 */
            BigInteger encKiGi = param.getEncKiGi();
            BigInteger encKiWi = param.getEncKiWi();

            BigInteger tmp1 = _hePrivKey.decrypt(encKiGi);
            BigInteger tmp2 = _hePrivKey.decrypt(encKiWi);
            EC.Scalar kigi = _curve.scalar(tmp1);
            EC.Scalar kiwi = _curve.scalar(tmp2);

            /* Accumulation data*/
            delta = delta.add(kigi);
            sigma = sigma.add(kiwi);
        }
        _kgi = delta.add(_sumK);
        _kwi = sigma.add(_sumW);

        return new MPCMessage(_myIndex, MPCMessage.BROADCAST, MPCMessage.PS_KGI, _kgi.toBytes());
    }

    public byte[] preSigningFinal(PreSigningFinalParam[] params) {
        EC.Scalar kg = _curve.scalar(0);

        for(int i=0; i<params.length; i++) {
            /* Parsing kgi from each messages.*/
            byte[] kgi = params[i].getKgi();
            kg = kg.add(_curve.scalar(kgi));
        }

        /* A part of ECDSA signature. */
        _r = _gG.scalarMul(kg.invert()).getAffineXCoord();

        return _r.toBytes();
    }

    public byte[] partialSign(byte[] message) {
        EC.Scalar msg = _curve.scalar(message);

        EC.Scalar rkxi = _r.mul(_kwi);
        EC.Scalar mki = msg.mul(_ki);
        return rkxi.add(mki).toBytes();
    }


    static class PreSigningStep2Param {

        private final int _otherIndex;
        private final byte[] _otherGiG;
        private final BigInteger _otherEncKi;
        private final PaillierPublicKey _otherPubKey;

        public PreSigningStep2Param(int index, byte[] encodedGiG, BigInteger encKi, PaillierPublicKey pubKey) {
            _otherIndex = index;
            _otherGiG = encodedGiG.clone();
            _otherEncKi = encKi;
            _otherPubKey = pubKey;
        }

        int getIndex() {
            return _otherIndex;
        }

        byte[] getEncodedGiG() {
            return _otherGiG;
        }

        BigInteger getEncKi() {
            return _otherEncKi;
        }

        PaillierPublicKey getHePublicKey() {
            return _otherPubKey;
        }
    }

    static class PreSigningStep3Param {

        private final BigInteger _otherEncKiGi;
        private final BigInteger _otherEncKiWi;

        public PreSigningStep3Param(BigInteger encKiGi, BigInteger encKiWi) {
            _otherEncKiGi = encKiGi;
            _otherEncKiWi = encKiWi;
        }

        public BigInteger getEncKiGi() {
            return _otherEncKiGi;
        }

        public BigInteger getEncKiWi() {
            return _otherEncKiWi;
        }

    }

    static class PreSigningFinalParam {

        private final byte[] _kgi;

        public PreSigningFinalParam(byte[] kgi) {
            _kgi = kgi.clone();
        }

        public byte[] getKgi() {
            return _kgi;
        }
    }

}
