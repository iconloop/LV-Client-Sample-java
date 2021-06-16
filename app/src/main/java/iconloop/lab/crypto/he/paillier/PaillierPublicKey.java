package iconloop.lab.crypto.he.paillier;

import com.google.gson.JsonObject;

import java.math.BigInteger;
import java.security.SecureRandom;

public class PaillierPublicKey {

    private final BigInteger _n;
    private final BigInteger _g;
    private final BigInteger _nSquare;

    public PaillierPublicKey(BigInteger N) {
        this(N, null);
    }

    public PaillierPublicKey(byte[] encoded) {
        this(new BigInteger(1, encoded), null);
    }

    public PaillierPublicKey(BigInteger N, BigInteger g) {
        _n = N;
        _g = g;
        _nSquare = _n.multiply(_n);
    }

    public BigInteger getN() {
        return _n;
    }

    public byte[] getEncoded() {
        return _n.toByteArray();
    }

    public BigInteger getG() {
        return _g;
    }

    public BigInteger getNSquare() {
        return _nSquare;
    }

    public BigInteger encrypt(BigInteger m) throws PaillierException {
        if(m.compareTo(_n) > 0)
            throw new PaillierException("Plaintext must be less than N");

        BigInteger g = null;
        if(_g != null)
            g = _g;
        else
            g = _n.add(BigInteger.ONE);

        BigInteger r = null;
        do {
            r = new BigInteger(_n.bitLength(), new SecureRandom());
        } while(r.gcd(_n).compareTo(BigInteger.ONE) != 0);

        return g.modPow(m, _nSquare).multiply(r.modPow(_n, _nSquare)).mod(_nSquare);
    }

    public BigInteger encrypt(BigInteger m, BigInteger r) throws PaillierException {
        if(m.compareTo(_n) > 0)
            throw new PaillierException("Plaintext must be less than N");

        BigInteger g = null;
        if(_g != null)
            g = _g;
        else
            g = _n.add(BigInteger.ONE);

        return g.modPow(m, _nSquare).multiply(r.modPow(_n, _nSquare)).mod(_nSquare);
    }

    public String toString() {
        return toJsonObject().toString();
    }

    public JsonObject toJsonObject() {
        JsonObject obj = new JsonObject();
        obj.addProperty("n", _n.toString(16));
        if(_g != null)
            obj.addProperty("g", _g.toString(16));
        return obj;
    }
}
