package iconloop.lab.crypto.ec.bouncycastle.curve;

import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.jose.ECKey;
import iconloop.lab.crypto.jose.JoseHeader;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public class ECUtils {

    private static final String ALGORITHM = "EC";

    public static KeyPair generateKeyPair(String curveName) throws Exception {
        AlgorithmParameterSpec pairParams;
        if(curveName.equals("curve25519")) {
            X9ECParameters ecP = CustomNamedCurves.getByName(curveName);
            pairParams = EC5Util.convertToSpec(ecP);
        } else {
            pairParams = new ECGenParameterSpec(curveName);
        }

        KeyPairGeneratorSpi.EC gen = new KeyPairGeneratorSpi.EC();
        gen.initialize(pairParams, new SecureRandom());
        return gen.generateKeyPair();
    }

    public static ECParameterSpec getECParameterSpec(String curveName){
        return ECNamedCurveTable.getParameterSpec(curveName);
    }

    public static BCECPublicKey getBCECPublicKey(ECParameterSpec paramSpec, BigInteger x, BigInteger y) {
        ECPoint point = paramSpec.getCurve().createPoint(x, y);
        return getBCECPublicKey(paramSpec, point);
    }

    public static BCECPublicKey getBCECPublicKey(ECParameterSpec paramSpec, byte[] encodedPoint) throws Exception {
        ECPoint point = paramSpec.getCurve().decodePoint(encodedPoint);
        return getBCECPublicKey(paramSpec, point);
    }

    public static BCECPublicKey getBCECPublicKey(ECParameterSpec paramSpec, ECPoint point) {
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, paramSpec);
        return new BCECPublicKey(ALGORITHM, keySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static byte[][] toUnsignedBytesFromBCECPublicKey(BCECPublicKey publicKey) {
        BigInteger x = publicKey.getW().getAffineX();
        BigInteger y = publicKey.getW().getAffineY();

        byte[][] point = new byte[2][];
        int fieldSize = publicKey.getParams().getCurve().getField().getFieldSize();
        point[0] = BigIntegers.asUnsignedByteArray((fieldSize + 7) / 8, x);
        point[1] = BigIntegers.asUnsignedByteArray((fieldSize + 7) / 8, y);

        return point;
    }

    public static byte[] toEncodedPointFromBCEDPublicKey(BCECPublicKey publicKey, boolean compressed) {
        return publicKey.getQ().getEncoded(compressed);
    }

    public static byte[] toUnsignedBytesFromBCECPrivateKey(BCECPrivateKey privateKey) {
        BigInteger d = privateKey.getS();
        int fieldSize = privateKey.getParams().getCurve().getField().getFieldSize();
        return BigIntegers.asUnsignedByteArray((fieldSize + 7)/8, d);
    }

    public static BCECPrivateKey getBCECPrivateKey(ECParameterSpec paramSpec, BigInteger d) {
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(d, paramSpec);
        return new BCECPrivateKey(ALGORITHM, keySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static BigInteger[] signECDSA(byte[] hashedMessage, ECPrivateKeyParameters keyParameters) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(true, keyParameters);
        return signer.generateSignature(hashedMessage);
    }

    public static BigInteger[] signECDSA(String curveName, byte[] hashedMessage, BCECPrivateKey privateKey) {
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        ECDomainParameters domainParam = new ECDomainParameters(spec.getCurve(), spec.getG(), spec.getN());
        ECPrivateKeyParameters keyParam = new ECPrivateKeyParameters(privateKey.getS(), domainParam);

        return signECDSA(hashedMessage, keyParam);
    }

    public static BigInteger[] signECDSA(byte[] hashedMessage, ECKey signerKey) {
        EC ec = new EC(signerKey.getCurveName());
        ECDomainParameters ecParams = ec.getDomainParameters();
        ECPrivateKeyParameters keyParam = new ECPrivateKeyParameters(signerKey.getPrivateKey().getS(), ecParams);

        return signECDSA(hashedMessage, keyParam);
    }

    public static boolean verifyECDSA(String curveSpec, byte[] hashedMessage, BCECPublicKey signerKey, BigInteger r, BigInteger s) {
        EC ec = new EC(curveSpec);
        ECDomainParameters ecParams = ec.getDomainParameters();
        ECPublicKeyParameters keyParam = new ECPublicKeyParameters(signerKey.getQ(), ecParams);

        return verifyECDSA(hashedMessage, keyParam, r, s);
    }

    public static boolean verifyECDSA(byte[] hashedMessage, ECKey signerKey, BigInteger r, BigInteger s) {
        EC ec = new EC(signerKey.getCurveName());
        ECDomainParameters ecParams = ec.getDomainParameters();
        ECPublicKeyParameters keyParam = new ECPublicKeyParameters(signerKey.getPublicKey().getQ(), ecParams);

        return verifyECDSA(hashedMessage, keyParam, r, s);
    }

    public static boolean verifyECDSA(byte[] hashedMessage, ECPublicKeyParameters keyParameters, BigInteger r, BigInteger s) {
        ECDSASigner verifier = new ECDSASigner();
        verifier.init(false, keyParameters);
        return verifier.verifySignature(hashedMessage, r, s);
    }

    public static byte[] encodeStdDSASignature(BigInteger sigR, BigInteger sigS) throws IOException {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(sigR));
        vector.add(new ASN1Integer(sigS));

        DERSequence seq = new DERSequence(vector);
        return seq.getEncoded();
    }

    public static BigInteger[] decodeStdDSASignature(byte[] signature) throws IOException {
        ASN1Sequence seq = DERSequence.getInstance(signature);
        ASN1Integer r = (ASN1Integer)seq.getObjectAt(0);
        ASN1Integer s = (ASN1Integer)seq.getObjectAt(1);

        return new BigInteger[]{r.getValue(), s.getValue()};
    }

}
