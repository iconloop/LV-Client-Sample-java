package iconloop.lab.crypto.he.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierPrivateKey {

    private final BigInteger _n;
    private final BigInteger _p;
    private final BigInteger _q;
    private final BigInteger _nSquare;
    private final BigInteger _phi;
    private final BigInteger _mu;
    private final BigInteger _one = BigInteger.ONE;

    public PaillierPrivateKey(BigInteger P, BigInteger Q) {
        this(P.multiply(Q), P, Q);
    }

    public PaillierPrivateKey(BigInteger N, BigInteger P, BigInteger Q) {
        _n = N;
        _p = P;
        _q = Q;
        _nSquare = N.multiply(N);
        // lambda = phi(N) = (P-1)(Q-1), g=N+1 case
        _phi =  P.subtract(_one).multiply(Q.subtract(_one));
        // mu = lambda^(-1), g=N+1 case
        _mu = _phi.modInverse(N);
    }

    public BigInteger genereateBaseG() {
        BigInteger pMinus1 = _p.subtract(_one);
        BigInteger qMinus1 = _q.subtract(_one);
        // lambda = (P-1)(Q-1)/gcd((P-1),(Q-1))
        BigInteger lambda = (pMinus1.multiply(qMinus1)).divide(pMinus1.gcd(qMinus1));
        BigInteger g;
        do {
            g = new BigInteger(_n.bitLength()/2, new SecureRandom());
            // mu^(-1) = (g^lambda - 1 mod N^2)/N
            // gcd( mu^(-1), N) = 1
        } while ((g.modPow(lambda, _nSquare).subtract(_one).divide(_n)).gcd(_n).intValue() != 1);
        return g;
    }

    public BigInteger getN() {
        return _n;
    }

    public BigInteger getNSquare() {
        return _nSquare;
    }

    public PaillierPublicKey getPublicKey() {
        return getPublicKey(null);
    }

    public PaillierPublicKey getPublicKey(BigInteger g) {
        return new PaillierPublicKey(_n, g);
    }

    public BigInteger decrypt(BigInteger c) {
        return decrypt(c, null);
    }

    public BigInteger decrypt(BigInteger c, BigInteger g) {
        BigInteger one = BigInteger.ONE;
        BigInteger lambda, mu;
        if(g != null && (g.compareTo(_n.add(one)) != 0)) {
            // lambda = (P-1)(Q-1)/gcd((P-1),(Q-1)) = phi/gcd((P-1),(Q-1))
            lambda = _phi.divide((_p.subtract(one).gcd(_q.subtract(one))));
            // (g^(lambda) mod n^2 - 1)/N ^(-1)
            mu = g.modPow(lambda, _nSquare).subtract(one).divide(_n).modInverse(_n);
        } else {
            lambda = _phi;
            mu = _mu;
        }

        return c.modPow(lambda, _nSquare).subtract(one).divide(_n).multiply(mu).mod(_n);
    }

}
