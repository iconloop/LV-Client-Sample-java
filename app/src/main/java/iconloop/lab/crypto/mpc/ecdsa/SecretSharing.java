package iconloop.lab.crypto.mpc.ecdsa;

import iconloop.lab.crypto.ec.bouncycastle.curve.EC;
import iconloop.lab.crypto.ec.bouncycastle.curve.EC.Scalar;

import java.math.BigInteger;

public class SecretSharing {


    // Evaluate value of polynomial.
    // return f(x)
    public static Scalar f(Scalar inputX, Scalar[] coefs) {
        int len = coefs.length;
        Scalar ret = coefs[len-1];

        for(int i = len-1; i>0; i--) {
            ret = ret.mul(inputX).add(coefs[i-1]);
        }
        return ret;
    }

    // Calculate lagrangian coefficient of a share.
    // return coefficient of F(0)
    public static Scalar li(EC curve, int[] xj, int xi) {
        Scalar li = curve.scalar(BigInteger.ONE);
        Scalar myID = curve.scalar(xi);

        for (int idx : xj) {
            if (xi != idx) {
                Scalar sIdx = curve.scalar(idx);
                Scalar tmp1 = myID.sub(sIdx).invert();
                Scalar tmp2 = curve.scalar(BigInteger.ZERO).sub(sIdx).mul(tmp1);
                li = li.mul(tmp2);
            }
        }
        return li;
    }

    // Calculate f(0) with more than (t+1) points.
    // return return F(0)
    public static Scalar interpolate(EC curve, int[] xi, Scalar[] fxi) {
        Scalar ret = curve.scalar(BigInteger.ZERO);

        for(int i =0; i<fxi.length; i++) {
            Scalar li = li(curve, xi, xi[i]);
            ret = ret.add(li.mul(fxi[i]));
        }
        return ret;
    }

}
