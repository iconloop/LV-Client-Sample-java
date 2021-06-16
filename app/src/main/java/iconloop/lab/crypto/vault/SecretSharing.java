package iconloop.lab.crypto.vault;


import java.security.SecureRandom;

public class SecretSharing {

    private final SecureRandom _random;
    private final int _n;
    private final int _t;

    /**
     * Constructor
     * @ random: random number generator
     * @ n: # of all Storages
     * @ t: # of threshold
     */
    public SecretSharing(SecureRandom random, int n, int t) {
        this._random = random;
        this._n = n;
        this._t = t;
    }

    /**
     * Splits the secret into n shares using shamir's secret sharing scheme
     *
     * @ secret: the secret to split
     * @ return: shares array whose each raw implies a share
     */
    public byte[][] split(byte[] secret) {

        // generate part values
        byte[][] shares = new byte[_n][secret.length+1];// "00" + "0000000000..." = "x"+"f(x)"
        int degree = _t;// - 1;

        //shares의 각 i-th byte를 구하는 for문
        for (int i = 0; i < secret.length; i++) {
            // for each byte, generate a random polynomial, p
            byte[] p = new byte[degree + 1];
            _random.nextBytes(p);
            p[0] = secret[i];
            //gen n points
            for(int j = 0; j < _n; j++) {
                shares[j][i] = GF256.eval(p, (byte)(j+1));
            }
        }

        for(int i = 0; i < _n; i++) {
            System.arraycopy(shares[i],0,shares[i],1, secret.length);
            shares[i][0] = (byte)(i+1);
        }


        return shares;
    }

    /**
     * Reconstruct original secret with the shares
     *
     * @ shares : arbitrary # of shares
     * @ return : the original secret
     */
    public byte[] reconstruct(byte[][] shares) {

        if (shares.length < (_t+1))
            return null;

        //to be returned
        final byte[] secret = new byte[shares[0].length-1];
        final int[] idx = new int[shares.length];


        for(int i = 0; i< shares.length; i++)
            idx[i] = shares[i][0];

        for (int i = 1; i < secret.length+1; i++) {

            final byte[] points = new byte[shares.length];
            for(int j = 0; j<shares.length;j++) {
                points[j] = shares[j][i];
            }
            secret[i-1] = interpolate(idx, points);
        }

        return secret;
    }

    private byte interpolate(int[] idx, byte[] points) {


        byte f0 = 0; // to be returned

        for (int i = 0; i < points.length; i++) {
            byte li = 1;
            for (int j = 0; j < points.length; j++) {
                if (i != j) {
                    li = GF256.mul(li, GF256.div(GF256.sub((byte)0, (byte)(idx[j])), GF256.sub((byte)(idx[i]), (byte)(idx[j]))));
                }
            }
            f0 = GF256.add(f0, GF256.mul(li, points[i]));
        }
        return f0;
    }
}