package iconloop.lab.crypto.jose;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECUtils;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import java.math.BigInteger;
import java.security.KeyPair;

public class ECKey {

    private static final String KTY = "EC";

    private final String _crv;
    private final BCECPublicKey _publicKey;
    private final BCECPrivateKey _privateKey;

    public ECKey(String crvName, BCECPublicKey publicKey, BCECPrivateKey privateKey) {
        _crv = crvName;
        _publicKey = publicKey;
        _privateKey = privateKey;
    }

    public ECKey(String crvName, KeyPair keyPair) {
        this(crvName, (BCECPublicKey)keyPair.getPublic(), (BCECPrivateKey)keyPair.getPrivate());
    }

    public static ECKey parse(JsonObject epkObject) throws JoseException {
        String kty = epkObject.get(JoseHeader.JWK_KEY_TYPE).getAsString();
        if(!kty.equals(KTY))
            throw new JoseException("Unsupported KeyType(" + kty + ")");

        String crv = epkObject.get(JoseHeader.JWK_CURVE_NAME).getAsString();

        String strX = epkObject.get(JoseHeader.JWK_KEY_X).getAsString();
        String strY = epkObject.get(JoseHeader.JWK_KEY_Y).getAsString();
        BigInteger x = new BigInteger(1, Utils.decodeFromBase64UrlSafeString(strX));
        BigInteger y = new BigInteger(1, Utils.decodeFromBase64UrlSafeString(strY));

        JsonElement tmp = epkObject.get(JoseHeader.JWK_KEY_D);
        BigInteger d = null;
        if(tmp != null) {
            String strD = tmp.getAsString();
            d = new BigInteger(1, Utils.decodeFromBase64UrlSafeString(strD));
        }

        ECParameterSpec paramSpec = ECUtils.getECParameterSpec(crv);
        BCECPublicKey publicKey;
        try {
            publicKey = ECUtils.getBCECPublicKey(paramSpec, x, y);
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }

        BCECPrivateKey privateKey = null;
        try {
            if(d != null)
                privateKey = ECUtils.getBCECPrivateKey(paramSpec, d);
        } catch (Exception e) {
            throw new JoseException(e.getMessage());
        }

        return new ECKey(crv, publicKey, privateKey);
    }

    public String getKeyType() {
        return KTY;
    }

    public String getCurveName() {
        return _crv;
    }

    public BCECPublicKey getPublicKey() {
        return _publicKey;
    }

    public byte[] getEncodedPointPublicKey(boolean compressed) {
        return _publicKey.getQ().getEncoded(compressed);
    }

    public BCECPrivateKey getPrivateKey() {
        return _privateKey;
    }

    public JsonObject toJsonObject() {
        return toJsonObject(false);
    }

    public JsonObject toJsonObject(boolean withPrivateKey) {
        JsonObject epk = new JsonObject();
        epk.addProperty(JoseHeader.JWK_KEY_TYPE, KTY);
        epk.addProperty(JoseHeader.JWK_CURVE_NAME, _crv);

        byte[][] bxy = ECUtils.toUnsignedBytesFromBCECPublicKey(_publicKey);
        String strX = Utils.encodeToBase64UrlSafeString(bxy[0]);
        String strY = Utils.encodeToBase64UrlSafeString(bxy[1]);
        epk.addProperty(JoseHeader.JWK_KEY_X, strX);
        epk.addProperty(JoseHeader.JWK_KEY_Y, strY);

        if(withPrivateKey) {
            byte[] bd = ECUtils.toUnsignedBytesFromBCECPrivateKey(_privateKey);
            String strD = Utils.encodeToBase64UrlSafeString(bd);
            epk.addProperty(JoseHeader.JWK_KEY_D, strD);
        }

        return epk;
    }

    public boolean equals(ECKey otherKey) {
        return  _crv.equals(otherKey.getCurveName()) && (_publicKey.equals(otherKey.getPublicKey()));
    }

}
