package LV.Client.Sample.java;

import iconloop.lab.util.JweClient;
import org.jose4j.json.internal.json_simple.JSONObject;
import org.jose4j.json.internal.json_simple.parser.JSONParser;
import org.jose4j.json.internal.json_simple.parser.ParseException;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;


class Samples {
    private final JweClient client;

    public void jweLowLevelSample() throws JoseException, IOException, InterruptedException {
        // An example showing the use of JSON Web Encryption (JWE) for LITE VAULT (iconloop)
        System.out.println("\n\n[ jweSample Run... ]");

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
        claims.setIssuedAtToNow();
        claims.setStringClaim("did", "issuer did of phone auth");
        senderJwe.setPayload(claims.toJson());

        // Set alg, enc values of the JWE header.
        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);

        String compactSerialization = senderJwe.getCompactSerialization();
        Key cek = new SecretKeySpec(senderJwe.getContentEncryptionKey(), "AESWrap");
        System.out.println("JWE compact serialization: " + compactSerialization);

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
        receiverJwe.setKey(cek);
        receiverJwe.setCompactSerialization(response_body);

        String plaintext = receiverJwe.getPlaintextString();
        System.out.println("\nplaintext: " + plaintext);
    }

    public void backupRequest() throws JoseException, IOException, InterruptedException {
        System.out.println("\n\n[ backupRequest Run... ]");

        // Set payload.
        JwtClaims claims = new JwtClaims();
        claims.setStringClaim("type", "BACKUP_REQUEST");
        claims.setIssuedAtToNow();
        claims.setStringClaim("did", "issuer did of phone auth");
        String payload = claims.toJson();
        String response = this.client.sendMessage(payload);
        System.out.println("response: " + response);
    }

    public void issueVid() throws IOException, JoseException, InterruptedException, ParseException {
        System.out.println("\n\n[ issueVid Run... ]");

        // load VP
        Path currentRelativePath = Paths.get("sample_vp.json");
        String vpPath = currentRelativePath.toAbsolutePath().toString();
        JSONParser parser = new JSONParser();
        JSONObject vpJsonObj = (JSONObject) parser.parse(new FileReader(vpPath));

        // Set payload.
        JwtClaims claims = new JwtClaims();
        claims.setStringClaim("type", "ISSUE_VID_REQUEST");
        claims.setIssuedAtToNow();
        claims.setClaim("vp", vpJsonObj);
        String payload = claims.toJson();
        String response = this.client.sendMessage(payload);
        System.out.println("response: " + response);
    }

    public void makeClue() {
        System.out.println("\n\n[ makeClue Run... ]");

    }

    public void storeClue() {
        System.out.println("\n\n[ storeClue Run... ]");

    }

    public void restoreData() {
        System.out.println("\n\n[ restoreData Run... ]");

    }

    public void runAllSequence() throws Exception {
        this.jweLowLevelSample();

        this.backupRequest();
        this.issueVid();
    }

    Samples() throws JoseException {
        String liteVaultManagerServerUri = "lv-manager.iconscare.com";
        String managerServerPublicKeyJson = "{\"crv\":\"P-256\",\"kty\":\"EC\"," +
                "\"x\":\"PIXG56FTMW0P1UgW6c5lRwlPuTFmZXuwpPmhwS_oFH4\"," +
                "\"y\":\"5BqfMR-NwN8JTBiIBzpmpFhVELiil17RUgfv7ci2ANs\"}";
        JsonWebKey jwk = JsonWebKey.Factory.newJwk(managerServerPublicKeyJson);

        this.client = new JweClient(liteVaultManagerServerUri, jwk.getKey());
    }
}

public class App {
    public static void main(String[] args) throws Exception {
        Samples samples = new Samples();
        samples.runAllSequence();
    }

    public String getGreeting() {
        return "Hello LITE VAULT!";
    }
}
