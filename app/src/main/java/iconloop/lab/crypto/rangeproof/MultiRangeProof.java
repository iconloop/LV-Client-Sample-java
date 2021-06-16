package iconloop.lab.crypto.rangeproof;

import iconloop.lab.crypto.bulletproof.BulletProof;
import iconloop.lab.crypto.bulletproof.BulletProofException;
import iconloop.lab.crypto.bulletproof.BulletProofTuple;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC;

import java.math.BigInteger;
import java.util.Vector;

public class MultiRangeProof {

    private final EC _curve;
    private final BulletProof _bp;

    private Vector<EC.Scalar> _secrets;
    private Vector<EC.Scalar> _cmRands;

    private Vector<Integer> _index;
    private Vector<EC.Point> _cms;
    private Vector<EC.Scalar> _rangeAs;
    private Vector<EC.Scalar> _rangeBs;

    public MultiRangeProof(String curveName, int secretBitLen, int maxM, String pubString) throws BulletProofException {
        _curve = new EC(curveName);
        _bp = new BulletProof(_curve, secretBitLen, maxM, pubString.getBytes());
    }

    public EC.Point bH(BigInteger b) {
        return _bp.getH().scalarMul(b);
    }

    public EC.Point commitment(BigInteger a, BigInteger b) {
        EC.Point bh = bH(b);
        return commitment(a, bh);
    }

    public EC.Point commitment(BigInteger a, EC.Point bH) {
        return _bp.getG().scalarMul(a).add(bH);
    }

    public void addSecret(BigInteger secret, BigInteger cmRand, BigInteger rangeA, BigInteger rangeB) {
        if(_secrets == null)
            _secrets = new Vector<EC.Scalar>();

        if(_cmRands == null)
            _cmRands = new Vector<EC.Scalar>();

        BigInteger r = new BigInteger("2").pow(_bp.getN());
        _secrets.add(_curve.scalar(secret.subtract(rangeA)));
        _secrets.add(_curve.scalar(r.subtract(rangeB).add(secret)));
        _cmRands.add(_curve.scalar(cmRand));
        _cmRands.add(_curve.scalar(cmRand));
    }

    public BulletProofTuple generateProof() throws BulletProofException {
        int m = _secrets.size();
        EC.Scalar[] secrets = new EC.Scalar[m];
        EC.Scalar[] cmRands = new EC.Scalar[m];

        int index = 0;
        for(EC.Scalar secret : _secrets) {
            secrets[index] = _secrets.get(index);
            index++;
        }
        index = 0;
        for(EC.Scalar cmRand : _cmRands) {
            cmRands[index] = _cmRands.get(index);
            index++;
        }

        return _bp.prove(secrets, cmRands);
    }

    public void addProofs(int index, EC.Point cm, BigInteger rangeA, BigInteger rangeB) {
        if(_index == null)
            _index = new Vector<Integer>();
        if(_cms == null)
            _cms = new Vector<EC.Point>();
        if(_rangeAs == null)
            _rangeAs = new Vector<EC.Scalar>();
        if(_rangeBs == null)
            _rangeBs = new Vector<EC.Scalar>();

        _index.add(index);
        _cms.add(cm);
        _rangeAs.add(_curve.scalar(rangeA));
        _rangeBs.add(_curve.scalar(rangeB));
    }

    public int verify(BulletProofTuple proof) {
        // Validation Stage 1: Proof Validation.
        int result = _bp.verify(proof);
        if(result != 0)
            return result;

        EC.Scalar R = _curve.scalar(new BigInteger("2").pow(_bp.getN())); //2^N
        EC.Point[] V = proof.getPointArray(BulletProofTuple.Points_V);
        int m = _index.size();
        for(int i=0; i<m; i++) {
            int index = _index.get(i);
                int tmp = checkProofs(_cms.get(i), V[2 * i], V[2 * i + 1], _rangeAs.get(i), _rangeBs.get(i), R);
                if (tmp > 0)
                    return (index * 100) + tmp;
        }
        return 0;
    }

    private int checkProofs(EC.Point commit, EC.Point V0, EC.Point V1, EC.Scalar rangeA, EC.Scalar rangeB, EC.Scalar R) {
        //Validation Stage 2: First Commitment Validation
        // V[0] + aG = {(s-a)G + rH} + aG = sG + rH
        EC.Point aG = _bp.getG().scalarMul(rangeA);
        if (!V0.add(aG).equals(commit))
            return 3;

        //Validation Stage 3: Second Commitment Validation
        // V[1] + bG - (2^N)G = {(2^N -b + s)G + rH} + bG - (2^N)G = sG + rH
        EC.Point bG = _bp.getG().scalarMul(rangeB); //bG
        EC.Point RG = _bp.getG().scalarMul(R); // (2^N)G

        if(!V1.add(bG).subtract(RG).equals(commit))
            return 4;

        return 0;
    }

}
