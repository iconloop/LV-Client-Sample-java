package LV.Client.Sample.java;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;


public class App {
    public static void main(String[] args) throws JoseException, IOException, InterruptedException {
        // An example showing the use of JSON Web Encryption (JWE) for LITE VAULT (iconloop)

        // Create a new Json Web Encryption object
        JsonWebEncryption senderJwe = new JsonWebEncryption();

        // Load JWK from json string.
        String jwkJson = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
                "\"x\":\"PIXG56FTMW0P1UgW6c5lRwlPuTFmZXuwpPmhwS_oFH4\"," +
                "\"y\":\"5BqfMR-NwN8JTBiIBzpmpFhVELiil17RUgfv7ci2ANs\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);
        senderJwe.setKey(jwk.getKey());

        // Set payload.
        JwtClaims claims = new JwtClaims();
        claims.setStringClaim("type", "BACKUP_REQUEST");
//        claims.setIssuedAtToNow();
        claims.setClaim("iat", 1623057440);
        claims.setStringClaim("did", "issuer did of phone auth");
        senderJwe.setPayload(claims.toJson());

        // Set alg, enc values of the JWE header.
        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);

        String compactSerialization = senderJwe.getCompactSerialization();
        byte[] cek = senderJwe.getContentEncryptionKey();
        System.out.println("JWE compact serialization: " + compactSerialization);

        // make jwk private key with cek.
        String jwkCEKJson = "{\"kty\":\"oct\",\"k\":\"" + Base64.getEncoder().encodeToString(cek) + "\"}";
        jwkCEKJson = jwkCEKJson.replaceAll("=", "");
        JsonWebKey jwkCEK = JsonWebKey.Factory.newJwk(jwkCEKJson);
        System.out.println("jwkCEKJson: " + jwkCEKJson);

        // Send Message as jwe_token to LV-Manager.
        HttpClient client = HttpClient.newHttpClient();

        // Create HTTP request object
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("http://lv-manager.iconscare.com/vault"))
                .POST(HttpRequest.BodyPublishers.noBody())
                .header("Authorization", compactSerialization)
                .build();

        // Send HTTP request
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        String response_body = response.body().replaceAll("\"", "");
        System.out.println("\nresponse: " + response_body);

        JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        receiverJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
        receiverJwe.setCompactSerialization(response_body);
        receiverJwe.setKey(jwkCEK.getKey());

        String plaintext = receiverJwe.getPlaintextString();
        System.out.println("plaintext: " + plaintext);
    }

    public String getGreeting() {
        return "Hello World!";
    }
}
