package iconloop.lab.crypto.he.paillier;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

public class PaillierUtils {

    public static PaillierPrivateKey generateKey(int keySize) throws PaillierException {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(keySize, new SecureRandom());
            keyPair = generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new PaillierException("No Such Algorithm(RSA)");
        }

        RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        BigInteger p = privKey.getPrimeP();
        BigInteger q = privKey.getPrimeQ();
        BigInteger n = privKey.getModulus();
        return new PaillierPrivateKey(n, p, q);
    }

    public static BigInteger cipherAdd(BigInteger c1, BigInteger c2, PaillierPublicKey publicKey) {
        return c1.multiply(c2).mod(publicKey.getNSquare());
    }

    // C ^ k
    public static BigInteger cipherScalarMul(BigInteger k, BigInteger c, PaillierPublicKey publicKey) {
        return c.modPow(k, publicKey.getNSquare());
    }

}
