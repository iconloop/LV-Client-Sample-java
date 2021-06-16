package iconloop.lab.crypto.bulletproof;

import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC;

import java.math.BigInteger;

/** Origianl Code : https://github.com/monero-project/research-lab/blob/master/source-code/StringCT-java/src/how/monero/hodl/bulletproof/MultiBulletproof.java */
public class BulletProof {
    private final EC _curve;
    private final int _logN;
    private final int _N;
    private final int _maxM;

    private final EC.Point _G;
    private final EC.Point _H;
    private final EC.Point[] _Gi;
    private final EC.Point[] _Hi;

    private final EC.Point PointZero;
    private final EC.Scalar ScalarZero;
    private final EC.Scalar ScalarOne;
    private final EC.Scalar ScalarTwo;
    private final EC.Scalar ScalarMinusOne;


    public BulletProof(EC curve, int secretBitLength, int maxM, byte[] pubString) throws BulletProofException {
        if((Integer.bitCount(secretBitLength) != 1) | (secretBitLength > 256) | (secretBitLength<0)) {
            throw new BulletProofException("N(secret length) Must be power of 2, and is on range 0 to 256");
        }
        _logN = Integer.numberOfTrailingZeros(secretBitLength);

        if((Integer.bitCount(maxM) != 1) | (maxM > 256) | (maxM<0)) {
            throw new BulletProofException("Max M(proof length) Must be power of 2, and is on range 0 to 256");
        }

        _curve = curve;
        PointZero = _curve.getInfinity();
        ScalarZero = _curve.ScalarZero();
        ScalarOne = _curve.scalar(1);
        ScalarTwo = _curve.scalar(2);
        ScalarMinusOne = _curve.scalar(-1);

        _N = secretBitLength;//(int)Math.pow(2, _logN);
        _maxM = maxM;

        _G = _curve.getBasePoint();
        _H = hashToPoint(pubString, _G.toBytes(true));

        int GiLength = _maxM * _N;
        _Gi = new EC.Point[GiLength];
        _Hi = new EC.Point[GiLength];

        for (int i = 1; i < GiLength+1; i++) {
            _Gi[i-1] = hashToPoint(pubString, BigInteger.valueOf(2*i).toByteArray());
            _Hi[i-1] = hashToPoint(pubString, BigInteger.valueOf(2*i).toByteArray());
        }

        // check collision
        for (int i = 0; i < GiLength; i++) {
            if (_Gi[i].equals(_H) || _Hi[i].equals(_H) || _Gi[i].equals(_G) || _Hi[i].equals(_G)) {
                throw new BulletProofException("Curve base points are not unique!");
            }
        }
    }

    public EC.Point getG() {
        return _H;
    }

    public EC.Point getH() {
        return _G;
    }

    public int getN() {
        return _N;
    }

    public BulletProofTuple prove(EC.Scalar[] v, EC.Scalar[] gamma) throws BulletProofException {
        int M = v.length;
        if((Integer.bitCount(M) != 1) | (M > _maxM)) {
            throw new BulletProofException("Length of V Must be power of 2, and is on range 0 to MaxM(" + _maxM + ")");
        }

        int logM = Integer.numberOfTrailingZeros(M);
        int logMN = logM + _logN;
        int MN = M * _N;

        EC.Point[] V = new EC.Point[M];
        V[0] = commitment(v[0], gamma[0]);
        EC.Scalar hashCache = hashToScalar(V[0].toBytes(true));
        for(int i=1; i<M; i++) {
            V[i] = commitment(v[i], gamma[i]);
            hashCache = hashToScalar(hashCache.toBytes(), V[i].toBytes(true));
        }

        // ref's eq. (41-42)
        EC.Scalar[] aL = new EC.Scalar[MN];
        EC.Scalar[] aR = new EC.Scalar[MN];

        for(int i=0; i<_N; i++) {
            for (int j = 0; j < M; j++) {
                if (v[j].getValue().testBit(i)) {
                    aL[j * _N + i] = ScalarOne;
                    aR[j * _N + i] = ScalarZero;
                } else {
                    aL[j * _N + i] = ScalarZero;
                    aR[j * _N + i] = ScalarMinusOne;
                }
            }
        }

        // ref's eq. (43-44)
        EC.Scalar alpha = _curve.getRandomScalar();
        EC.Point A = vectorCommitment(aL, aR).add(_G.scalarMul(alpha));

        // ref's eq. (45-47)
        EC.Scalar[] sL = new EC.Scalar[MN];
        EC.Scalar[] sR = new EC.Scalar[MN];
        for (int i = 0; i < MN; i++) {
            sL[i] = _curve.getRandomScalar();
            sR[i] = _curve.getRandomScalar();
        }
        EC.Scalar rho = _curve.getRandomScalar();
        EC.Point S = vectorCommitment(sL,sR).add(_G.scalarMul(rho));

        // ref's eq. (48-50)
        hashCache = hashToScalar(hashCache.toBytes(), A.toBytes(true), S.toBytes(true));
        EC.Scalar y = hashCache;

        hashCache = hashToScalar(hashCache.toBytes());
        EC.Scalar z = hashCache;

        // ref's eq. (58-59) or (71)
        // Coefficients of Polynomials l(x), r(x)
        EC.Scalar[] l0;
        EC.Scalar[] l1;
        EC.Scalar[] r0 = new EC.Scalar[MN];
        EC.Scalar[] r1;

        l0 = vectorSubtract(aL, vectorScalar(vectorPowers(ScalarOne, MN), z));
        l1 = sL;

        EC.Scalar[] zerosTwos = new EC.Scalar[MN];
        for(int i=0; i<MN; i++) {
            zerosTwos[i] = ScalarZero;
            for (int j = 1; j <= M; j++) {
                EC.Scalar temp = ScalarZero;
                if (i >= (j-1)*_N && i < j*_N)
                    temp = ScalarTwo.pow(i-(j-1)*_N);
                zerosTwos[i] = zerosTwos[i].add(z.pow(1+j).mul(temp));
            }
            r0[i] = aR[i].add(z).mul(y.pow(i)).add(zerosTwos[i]);
        }

        r1 = hadamardScalar(vectorPowers(y, MN),sR);

        // ref's eq. (52-53)
        EC.Scalar t1 = innerProduct(l0, r1).add(innerProduct(l1,r0));
        EC.Scalar t2 = innerProduct(l1,r1);

        EC.Scalar tau1 = _curve.getRandomScalar();
        EC.Scalar tau2 = _curve.getRandomScalar();

        EC.Point T1 = _H.scalarMul(t1).add(_G.scalarMul(tau1));
        EC.Point T2 = _H.scalarMul(t2).add(_G.scalarMul(tau2));

        // ref's eq. (56)
        hashCache = hashToScalar(hashCache.toBytes(), z.toBytes(), T1.toBytes(true), T2.toBytes(true));
        EC.Scalar x = hashCache;

        // ref's eq. (58-60)
        EC.Scalar[] l = l0;
        l = vectorAdd(l, vectorScalar(l1, x));
        EC.Scalar[] r = r0;
        r = vectorAdd(r, vectorScalar(r1, x));
        EC.Scalar t = innerProduct(l, r);

        // ref's eq. (61)
        EC.Scalar taux = tau2.mul(x.square()).add(tau1.mul(x));
        for(int j=1; j<=M; j++) {
            taux = taux.add(z.pow(j+1).mul(gamma[j-1]));
        }

        // ref's eq. (62)
        EC.Scalar mu = x.mul(rho).add(alpha);

        // ref's eq. (26-27)
        hashCache = hashToScalar(hashCache.toBytes(), x.toBytes(), taux.toBytes(), mu.toBytes(), t.toBytes());
        EC.Scalar x_ip = hashCache;

        int nprime = MN;
        EC.Point[] gPrime = new EC.Point[MN];
        EC.Point[] hPrime = new EC.Point[MN];
        EC.Scalar[] aPrime = new EC.Scalar[MN];
        EC.Scalar[] bPrime = new EC.Scalar[MN];

        EC.Scalar invY = y.invert();
        for (int i = 0; i < MN; i++) {
            gPrime[i] = _Gi[i];
            hPrime[i] = _Hi[i].scalarMul(invY.pow(i));
            aPrime[i] = l[i];
            bPrime[i] = r[i];
        }

        EC.Point[] L = new EC.Point[logMN];
        EC.Point[] R = new EC.Point[logMN];
        int round = 0;
        EC.Scalar[] w = new EC.Scalar[logMN];

        while (nprime > 1) {
            // ref's eq. (20)
            nprime = nprime >> 1;

            // ref's eq. (21-22)
            EC.Scalar cL = innerProduct(scalarSlice(aPrime,0, nprime), scalarSlice(bPrime, nprime, bPrime.length));
            EC.Scalar cR = innerProduct(scalarSlice(aPrime, nprime, aPrime.length), scalarSlice(bPrime,0, nprime));

            // ref's eq. (23-24)
            L[round] = vectorCommitmentCustom(curveSlice(gPrime, nprime, gPrime.length), curveSlice(hPrime,0, nprime), scalarSlice(aPrime,0, nprime), scalarSlice(bPrime, nprime, bPrime.length)).add(_H.scalarMul(cL.mul(x_ip)));
            R[round] = vectorCommitmentCustom(curveSlice(gPrime,0, nprime), curveSlice(hPrime, nprime, hPrime.length), scalarSlice(aPrime, nprime, aPrime.length), scalarSlice(bPrime,0, nprime)).add(_H.scalarMul(cR.mul(x_ip)));

            // ref's eq. (26-27)
            hashCache = hashToScalar(hashCache.toBytes(), L[round].toBytes(true), R[round].toBytes(true));
            w[round] = hashCache;

            // ref's eq. (29-30)
            gPrime = hadamardPoint(vectorScalar2(curveSlice(gPrime,0, nprime), w[round].invert()), vectorScalar2(curveSlice(gPrime, nprime, gPrime.length), w[round]));
            hPrime = hadamardPoint(vectorScalar2(curveSlice(hPrime,0, nprime), w[round]), vectorScalar2(curveSlice(hPrime, nprime, hPrime.length), w[round].invert()));

            // ref's eq. (33-34)
            aPrime = vectorAdd(vectorScalar(scalarSlice(aPrime,0, nprime), w[round]), vectorScalar(scalarSlice(aPrime, nprime, aPrime.length), w[round].invert()));
            bPrime = vectorAdd(vectorScalar(scalarSlice(bPrime,0, nprime), w[round].invert()), vectorScalar(scalarSlice(bPrime, nprime, bPrime.length), w[round]));

            round += 1;
        }

        return new BulletProofTuple(_curve, V, A, S, T1, T2, taux, mu, L, R, aPrime[0], bPrime[0], t);
    }

    public int verify(BulletProofTuple proof) {
        EC.Point[] V = proof.getPointArray(BulletProofTuple.Points_V);
        EC.Point[] L = proof.getPointArray(BulletProofTuple.Points_L);
        EC.Point[] R = proof.getPointArray(BulletProofTuple.Points_R);
        EC.Point A = proof.getPoint(BulletProofTuple.Point_A);
        EC.Point S = proof.getPoint(BulletProofTuple.Point_S);
        EC.Point T1 = proof.getPoint(BulletProofTuple.Point_T1);
        EC.Point T2 = proof.getPoint(BulletProofTuple.Point_T2);

        EC.Scalar taux = proof.getScalar(BulletProofTuple.Scalar_Taux);
        EC.Scalar mu = proof.getScalar(BulletProofTuple.Scalar_Mu);
        EC.Scalar a = proof.getScalar(BulletProofTuple.Scalar_A);
        EC.Scalar b = proof.getScalar(BulletProofTuple.Scalar_B);
        EC.Scalar t = proof.getScalar(BulletProofTuple.Scalar_T);

        int logMN = L.length;
        int M = (int) Math.pow(2, logMN) / _N;
        int MN = M * _N;

        // Reconstruct the challenges, ref's eq (96)
        EC.Scalar hashCache = hashToScalar(V[0].toBytes(true));
        for (int i = 1; i < M; i++) {
            hashCache = hashToScalar(hashCache.toBytes(), V[i].toBytes(true));
        }
        hashCache = hashToScalar(hashCache.toBytes(), A.toBytes(true), S.toBytes(true));
        EC.Scalar y = hashCache;

        hashCache = hashToScalar(hashCache.toBytes());
        EC.Scalar z = hashCache;

        hashCache = hashToScalar(hashCache.toBytes(), z.toBytes(), T1.toBytes(true), T2.toBytes(true));
        EC.Scalar x = hashCache;

        hashCache = hashToScalar(hashCache.toBytes(), x.toBytes(), taux.toBytes(), mu.toBytes(), t.toBytes());
        EC.Scalar x_ip = hashCache;

//        // First check eq. Basic: (65)
//        EC.Scalar ip_1nm_ynm = y.pow(MN).sub(_ScalarOne).mul(y.sub(_ScalarOne).invert());
//        EC.Scalar ip_1n_2n = _curve.scalar(2).pow(_N).sub(_ScalarOne);
//        EC.Scalar sigma = z.pow(3).add(z.pow(4));
//        EC.Scalar delta = z.sub(z.square()).mul(ip_1nm_ynm).sub(sigma.mul(ip_1n_2n));
//        Point vSum = V[0].scalarMul(z.pow(2)).add(V[1].scalarMul(z.pow(3)));
//        EC.Point D1 = T1.scalarMul(x);
//        EC.Point D2 = T2.scalarMul(x.square());
//        EC.Point Check1 = _G.scalarMul(t).add(_H.scalarMul(taux)).subtract(_G.scalarMul(delta).add(vSum).add(D1).add(D2));

        // First check eq. Aggregated: (72)
        EC.Scalar k = ScalarZero.sub(z.square().mul(innerProduct(vectorPowers(ScalarOne, MN), vectorPowers(y, MN))));
        for (int j = 1; j <= M; j++) {
            k = k.sub(z.pow(j + 2).mul(innerProduct(vectorPowers(ScalarOne, _N), vectorPowers(ScalarTwo, _N))));
        }
        EC.Scalar tc = t.sub(k.add(z.mul(innerProduct(vectorPowers(ScalarOne, MN), vectorPowers(y, MN)))));

        EC.Point vSum = PointZero;
        for (int i = 0; i < M; i++)
            vSum = vSum.add(V[i].scalarMul(z.pow(i + 2)));

        EC.Point D1 = T1.scalarMul(x);
        EC.Point D2 = T2.scalarMul(x.square());
        EC.Point Check1 = _H.scalarMul(tc).add(_G.scalarMul(taux)).subtract(vSum).subtract(D1).subtract(D2);
        if (!Check1.isInfinity()) {
            return 1;
        }

        // Second check eq. Basic: (66-67), Aggregated: next eq of (72) or (105)
        EC.Point Z1 = A.add(S.scalarMul(x));

        // ref's eq. (96)
        EC.Scalar[] w = new EC.Scalar[logMN];
        for (int i = 0; i < logMN; i++) {
            hashCache = hashToScalar(hashCache.toBytes(), L[i].toBytes(true), R[i].toBytes(true));
            w[i] = hashCache;
        }

        // ref's eq. (99-104)
        EC.Scalar invY = y.invert();
        EC.Scalar[] l = new EC.Scalar[MN];
        EC.Scalar[] r = new EC.Scalar[MN];
        for (int i = 0; i < MN; i++) {
            l[i] = a;
            r[i] = b.mul(invY.pow(i));

            for (int j = 0; j < logMN; j++) {
                int bit = (i >> j) & 0x01;
                if (bit == 1) {
                    l[i] = l[i].mul(w[w.length - j - 1]);
                    r[i] = r[i].mul(w[w.length - j - 1].invert());
                } else {
                    l[i] = l[i].mul(w[w.length - j - 1].invert());
                    r[i] = r[i].mul(w[w.length - j - 1]);
                }
            }

            l[i] = l[i].add(z);
            r[i] = r[i].sub(z.mul(y.pow(i)).add(z.pow(2 + i / _N).mul(ScalarTwo.pow(i % _N))).mul(invY.pow(i)));
        }

        EC.Point LRSum = PointZero;
        for (int i = 0; i < logMN; i++) {
            LRSum = LRSum.add(L[i].scalarMul(w[i].square()));
            LRSum = LRSum.add(R[i].scalarMul(w[i].invert().square()));
        }

        EC.Scalar z3 = (t.sub(a.mul(b))).mul(x_ip); // (t-ab)
        EC.Point Check2 = Z1.add(_G.scalarMul(ScalarZero.sub(mu))).add(LRSum).add(_H.scalarMul(z3));

        for (int i = 0; i < MN; i++) {
            Check2 = Check2.subtract(_Gi[i].scalarMul(l[i])).subtract(_Hi[i].scalarMul(r[i]));
        }

        if (!Check2.equals(PointZero)) {
            return 2;
        }

        return 0;
    }

    public byte[] digest(byte[]... arrays) {
        return Utils.sha256Digest(Utils.concat(arrays));
    }

    // aG + bH
    public EC.Point commitment(EC.Scalar a, EC.Scalar b) {
        return _H.scalarMul(a).add(_G.scalarMul(b));
    }

    public EC.Point hashToPoint(byte[]... arrays) {
        EC.Scalar scalar = _curve.scalar(digest(arrays));
        return _curve.getBasePoint().scalarMul(scalar);
    }

    public EC.Scalar hashToScalar(byte[]... arrays) {
        return _curve.scalar(digest(arrays));
    }

    /* Given two scalar arrays, construct a vector commitment */
    public EC.Point vectorCommitment(EC.Scalar[] a, EC.Scalar[] b) {
        EC.Point result = PointZero;
        for (int i=0; i<a.length; i++) {
            result = result.add(_Gi[i].scalarMul(a[i]));
            result = result.add(_Hi[i].scalarMul(b[i]));
        }
        return result;
    }

    /* Given a scalar, construct a vector of powers */
    public EC.Scalar[] vectorPowers(EC.Scalar x, int size) {
        EC.Scalar[] result = new EC.Scalar[size];
        result[0] = ScalarOne;
        for (int i=1; i<size; i++)  {
            result[i] = result[i-1].mul(x);
        }
        return result;
    }

    /* Add two vectors */
    public EC.Scalar[] vectorAdd(EC.Scalar[] a, EC.Scalar[] b) {
        EC.Scalar[] result = new EC.Scalar[a.length];
        for (int i=0; i<a.length; i++) {
            result[i] = a[i].add(b[i]);
        }
        return result;
    }

    /* Subtract two vectors */
    public EC.Scalar[] vectorSubtract(EC.Scalar[] a, EC.Scalar[] b) {
        EC.Scalar[] result = new EC.Scalar[a.length];
        for (int i=0; i<a.length; i++) {
            result[i] = a[i].sub(b[i]);
        }
        return result;
    }

    /* Multiply a scalar and a vector */
    public EC.Scalar[] vectorScalar(EC.Scalar[] a, EC.Scalar x) {
        EC.Scalar[] result = new EC.Scalar[a.length];
        for (int i=0; i<a.length; i++) {
            result[i] = a[i].mul(x);
        }
        return result;
    }

    /* Exponentiate a curve vector by a scalar */
    public EC.Point[] vectorScalar2(EC.Point[] A, EC.Scalar x) {
        EC.Point[] Result = new EC.Point[A.length];
        for (int i = 0; i < A.length; i++) {
            Result[i] = A[i].scalarMul(x);
        }
        return Result;
    }

    /* Given two scalar arrays, construct the HadamardScalar product */
    public EC.Scalar[] hadamardScalar(EC.Scalar[] a, EC.Scalar[] b) {
        EC.Scalar[] result = new EC.Scalar[a.length];
        for (int i=0; i<a.length; i++) {
            result[i] = a[i].mul(b[i]);
        }
        return result;
    }

    /* Given two curvepoint arrays, construct the HadamardScalar product */
    public EC.Point[] hadamardPoint(EC.Point[] A, EC.Point[] B) {
        EC.Point[] Result = new EC.Point[A.length];
        for (int i = 0; i < A.length; i++) {
            Result[i] = A[i].add(B[i]);
        }
        return Result;
    }

    /* Given two scalar arrays, construct the inner product */
    public EC.Scalar innerProduct(EC.Scalar[] a, EC.Scalar[] b) {
        EC.Scalar result = ScalarZero;
        for (int i=0; i<a.length; i++) {
            result = result.add(a[i].mul(b[i]));
        }
        return result;
    }

    /* Compute the slice of a scalar vector */
    public EC.Scalar[] scalarSlice(EC.Scalar[] a, int start, int stop) {
        EC.Scalar[] result = new EC.Scalar[stop-start];
        for (int i=start; i<stop; i++) {
            result[i-start] = a[i];
        }
        return result;
    }

    /* Compute the slice of a curvepoint vector */
    public EC.Point[] curveSlice(EC.Point[] a, int start, int stop) {
        EC.Point[] Result = new EC.Point[stop-start];
        for (int i=start; i<stop; i++) {
            Result[i-start] = a[i];
        }
        return Result;
    }

    /* Compute the inverse of a scalar, the stupid way */
    public EC.Scalar invert(EC.Scalar x) {
        EC.Scalar inverse = x.invert();
        return inverse;
    }

    /* Compute a custom vector-scalar commitment */
    public EC.Point vectorCommitmentCustom(EC.Point[] A, EC.Point[] B, EC.Scalar[] a, EC.Scalar[] b) {
        EC.Point Result = PointZero;
        for (int i=0; i<a.length; i++) {
            Result = Result.add(A[i].scalarMul(a[i]));
            Result = Result.add(B[i].scalarMul(b[i]));
        }
        return Result;
    }

}
