package iconloop.lab.crypto.ec.bouncycastle.curve;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class EC {

    private static String _curveName;
    private static ECParameterSpec _spec;
    private static BigInteger _scalarMod;

    public EC(String curveName) {
        _curveName = curveName;
        ECParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        if(spec == null)
            throw new IllegalArgumentException(curveName + " is not supported.");

        _spec = spec;
        _scalarMod = spec.getN();
    }

    public ECParameterSpec getSpec() {
        return _spec;
    }

    public ECDomainParameters getDomainParameters() {
        return new ECDomainParameters(_spec.getCurve(), _spec.getG(), _spec.getN(), _spec.getH());
    }

    public String getCurveName() {
        return _curveName;
    }

    public int getFieldSize() {
        return _spec.getCurve().getFieldSize();
    }

    public Point point(byte[] encoded) {
        ECPoint point = _spec.getCurve().decodePoint(encoded);
        return new Point(point);
    }

    public Point getInfinity() {
        return new Point(_spec.getCurve().getInfinity());
    }
    public Point getBasePoint() {
        return new Point(_spec.getG());
    }

    public Scalar scalar(byte[] bytes) {
        return new Scalar(new BigInteger(1, bytes));
    }

    public Scalar scalar(int input) {
        return new Scalar(BigInteger.valueOf(input));
    }

    public Scalar scalar(BigInteger value) {
        return new Scalar(value);
    }

    public Scalar ScalarZero() {
        return new Scalar(BigInteger.ZERO);
    }

    public Scalar getRandomScalar() {
        return getRandomScalar(_spec.getN().bitLength());
    }

    public Scalar getRandomScalar(int bitLength) {
        Random rng = new SecureRandom();

        BigInteger ret;
        do {
            ret = new BigInteger(bitLength, rng);
        } while (ret.equals(BigInteger.ZERO));

        return new Scalar(ret);
    }

    public class Point {
        private ECPoint _point;

        protected Point(ECPoint point) {
            _point = point;
        }

        public ECParameterSpec getSpec() {
            return _spec;
        }

        public ECPoint getECPoint() {
            return _point;
        }

        /* Arithmetic Operations. */
        public Point add(Point a) {
            return new Point(_point.add(a.getECPoint()));
        }

        public Point subtract(Point a) {
            return new Point(_point.subtract(a.getECPoint()));
        }

        public Point scalarMul(BigInteger a) {
            return scalarMul(new Scalar(a));
        }

        public Point scalarMul(Scalar a) {
            return new Point(_point.multiply(a.getValue()));
        }

        /* Logical Operations. */
        public boolean isInfinity() {
            return _point.isInfinity();
        }

        public boolean equals(Object in) {
            if (in instanceof Point) {
                return _point.equals(((Point)in).getECPoint());
            }
            return false;
        }

        /* Theoretical Operations. */
        public Point normalize() {
            return new Point(_point.normalize());
        }
        public Scalar getAffineXCoord(){
            ECPoint point = _point.normalize();
            return new Scalar(point.getAffineXCoord().toBigInteger());
        }

        /* Class Outer. */

        /**
         * Return point as encoded byte-array
         * @return encoded byte-array with prefix 0x02 or 0x03.
         */
        public byte[] toBytes(boolean compressed) { return _point.getEncoded(compressed); }

        /**
         * Return point as encoded Hex String.
         * @return encoded string with prefix 0x02 or 0x03.
         */
        public String toString() { return Hex.toHexString(_point.getEncoded(true)); }
    }

    public class Scalar {
        // data
        private BigInteger _value;

        /**
         * Constructor by BigInteger.
         * @param value Arbitrary BigInteger
         */
        protected Scalar(BigInteger value) {
            _value = value.mod(_scalarMod);
        }

        public BigInteger getValue() {
            return _value;
        }

        /* Arithmetic Operations. */
        public Scalar add(Scalar a) {
            return new Scalar(_value.add(a.getValue()));
        }

        public Scalar sub(Scalar a) {
            return new Scalar(_value.subtract(a.getValue()));
        }

        public Scalar mul(Scalar a) {
            return new Scalar(_value.multiply(a.getValue()));
        }

        public Scalar square() {
            return new Scalar(_value.modPow(BigInteger.valueOf(2), _scalarMod));
        }

        public Scalar pow(int b) {
            return new Scalar(_value.modPow(BigInteger.valueOf(b), _scalarMod));
        }

        public Scalar invert() {
            return new Scalar(_value.modInverse(_scalarMod));
        }

        /* Logical Operations. */
        @Override
        public boolean equals(Object a) {

            if (a instanceof Scalar) {
                Scalar in =  (Scalar) a;
                return _value.equals(in.getValue());
            }
            return false;
        }

        /* Class Outer. */
        public byte[] toBytes() {
            return BigIntegers.asUnsignedByteArray((getFieldSize() + 7) / 8, _value);
        }

        public String toString() {
            return Hex.toHexString(toBytes());
        }
    }

}
