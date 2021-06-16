package iconloop.lab.crypto.jose;

import com.google.gson.JsonObject;
import iconloop.lab.crypto.common.Utils;
import iconloop.lab.crypto.ec.bouncycastle.curve.ECUtils;

import java.math.BigInteger;

public class JwsSign {

    private final String _alg;
    private final String _kid;

    public JwsSign(String algorithm, String kid) {
        _alg = algorithm;
        _kid = kid;
    }

    public String sign(JsonObject payload, ECKey signerKey, boolean setJwk) {
        byte[] b64Header = null;
        if(setJwk)
            b64Header = makeHeader(signerKey);
        else
            b64Header = makeHeader(null);

        String strPayload = payload.toString();
        byte[] b64Payload = Utils.encodeToBase64UrlSafe(strPayload);

        byte[] input = Utils.concat(b64Header, ".".getBytes(), b64Payload);

        String b64Signature = "";
        if(_alg.equals(JoseHeader.JWS_ALG_ES256)) {
            byte[] toBeSigned = Utils.sha256Digest(input);
            BigInteger[] sign = ECUtils.signECDSA(toBeSigned, signerKey);
            b64Signature = encodeECDSASignature(sign[0], sign[1]);
        }

        return new String(b64Header) + "." + new String(b64Payload) + "." + b64Signature;
    }

    private byte[] makeHeader(ECKey signerKey) {
        JoseHeader header = new JoseHeader(_alg, _kid, null, signerKey);
        String strHeader = header.toString();
        return Utils.encodeToBase64UrlSafe(strHeader);
    }

    private String encodeECDSASignature(BigInteger r, BigInteger s) {
        int rSize = 32;
        byte[] rBytes = Utils.bigIntToUnsigned(r, rSize);
        byte[] sBytes = Utils.bigIntToUnsigned(s, rSize);

        byte[] sig = new byte[rSize*2];
        System.arraycopy(rBytes, 0, sig, 0, rSize);
        System.arraycopy(sBytes, 0, sig, rSize, rSize);

        return Utils.encodeToBase64UrlSafeString(sig);
    }
}
