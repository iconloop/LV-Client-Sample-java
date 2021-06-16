package iconloop.lab.crypto.rangeproof;

import iconloop.lab.crypto.bulletproof.BulletProof;
import iconloop.lab.crypto.bulletproof.BulletProofException;
import iconloop.lab.crypto.bulletproof.BulletProofTuple;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC.Point;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC.Scalar;

import java.math.BigInteger;

public class RangeProof {

    public final int MAX_M = 2;
    private final EC _curve;
    private final BulletProof _bp;

    public RangeProof(String curveName, int secretBitLen, String pubString) throws BulletProofException {
        _curve = new EC(curveName);
        _bp = new BulletProof(_curve, secretBitLen, MAX_M, pubString.getBytes());
    }

    public Point bH(BigInteger b) {
        return _bp.getH().scalarMul(b);
    }

    public Point commitment(BigInteger a, BigInteger b) {
        Point bh = bH(b);
        return commitment(a, bh);
    }

    public Point commitment(BigInteger a, Point bH) {
        return _bp.getG().scalarMul(a).add(bH);
    }

    // secret in [rangeA, rangeB)
    public BulletProofTuple generateProof(BigInteger secret, BigInteger cmRand, BigInteger rangeA, BigInteger rangeB) throws BulletProofException {
        Scalar[] secrets = new Scalar[2];
        Scalar[] cmRands = new Scalar[2];

        BigInteger r = new BigInteger("2").pow(_bp.getN());

        secrets[0] = _curve.scalar(secret.subtract(rangeA));          // secret - a
        secrets[1] = _curve.scalar(r.subtract(rangeB).add(secret));   // 2^N - b + secret
        cmRands[0] = _curve.scalar(cmRand);
        cmRands[1] = _curve.scalar(cmRand);

        return _bp.prove(secrets, cmRands);
    }

    public int verify(Point commit, BulletProofTuple proof, BigInteger rangeA, BigInteger rangeB) {

        // Validation Stage 1: Proof Validation.
        int result = _bp.verify(proof);
        if(result != 0)
            return result;

        Point[] V = proof.getPointArray(BulletProofTuple.Points_V);

        //Validation Stage 2: First Commitment Validation
        // V[0] + aG = {(s-a)G + rH} + aG = sG + rH
        Point aG = _bp.getG().scalarMul(_curve.scalar(rangeA));
        if (!V[0].add(aG).equals(commit))
            return 3;

        //Validation Stage 3: Second Commitment Validation
        // V[1] + bG - (2^N)G = {(2^N -b + s)G + rH} + bG - (2^N)G = sG + rH
        Scalar R = _curve.scalar(new BigInteger("2").pow(_bp.getN())); //2^N
        Point bG = _bp.getG().scalarMul(_curve.scalar(rangeB)); //bG
        Point RG = _bp.getG().scalarMul(R); // (2^N)G

        if(!V[1].add(bG).subtract(RG).equals(commit))
            return 4;

        return 0; // All of Validations success
    }

}
