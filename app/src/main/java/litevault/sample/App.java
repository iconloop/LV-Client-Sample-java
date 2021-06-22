package litevault.sample;

import iconloop.lab.util.Clue;
import iconloop.lab.util.JweClient;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.jose4j.json.internal.json_simple.JSONArray;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


class Samples {
    private final JweClient client;
    private JSONObject storages;

    private JSONObject loadVP() throws IOException, ParseException {
        // load VP
        Path currentRelativePath = Paths.get("sample_vp.json");
        String vpPath = currentRelativePath.toAbsolutePath().toString();
        JSONParser parser = new JSONParser();
        return (JSONObject) parser.parse(new FileReader(vpPath));
    }

    public void jweLowLevelSample() throws JoseException, IOException, InterruptedException {
        // An example showing the use of JSON Web Encryption (JWE) for LITE VAULT (iconloop)
        System.out.println("\n\n[ jweLowLevelSample Run... ]");

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

        // Set payload.
        JwtClaims claims = new JwtClaims();
        claims.setStringClaim("type", "ISSUE_VID_REQUEST");
        claims.setIssuedAtToNow();
        claims.setClaim("vp", this.loadVP());
        String payload = claims.toJson();
        String response = this.client.sendMessage(payload);
        System.out.println("response: " + response);

        JSONParser parser = new JSONParser();
        this.storages = (JSONObject) parser.parse(response);
    }

    public String[] makeClue(String data) throws InvalidCipherTextException {
        System.out.println("\n\n[ makeClue Run... ]");

        Clue clue = new Clue();
        int storageNumber = 3;
        int threshold = 2;
        String[] clues = clue.makeClue(storageNumber, threshold, data.getBytes(StandardCharsets.UTF_8));
        System.out.println("clues: " + Arrays.toString(clues));
        return clues;
    }

    public void tokenRequest() throws IOException, ParseException, JoseException, InterruptedException {
        System.out.println("\n\n[ tokenRequest Run... ]");

        System.out.println("Storages: " + this.storages.get("storages").toString());
        JSONArray storageArray = (JSONArray)this.storages.get("storages");
        JSONArray newStorageArray = new JSONArray();

        for (Object obj : storageArray) {
            JSONObject storage = (JSONObject) obj;
            System.out.println("Storage: " + storage.toString());

            // JWE client for Storage Server.
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(storage.get("key").toString());
            JweClient client = new JweClient(storage.get("target").toString(), jwk.getKey());

            // Set payload.
            JwtClaims claims = new JwtClaims();
            claims.setStringClaim("type", "TOKEN_REQUEST");
            claims.setIssuedAtToNow();
            claims.setStringClaim("vID", this.storages.get("vID").toString());
            claims.setClaim("vp", this.loadVP());
            String payload = claims.toJson();
            String response = client.sendMessage(payload);
            System.out.println("response: " + response);

            JSONParser parser = new JSONParser();
            JSONObject storageToken = (JSONObject) parser.parse(response);

            storage.put("token", storageToken.get("token").toString());
            newStorageArray.add(storage);
        }

        this.storages.put("storages", newStorageArray);
        System.out.println("Storages(with token): " + this.storages.get("storages").toString());
    }

    public void storeClue(String[] clues) throws JoseException, IOException, InterruptedException {
        System.out.println("\n\n[ storeClue Run... ]");

        JSONArray storageArray = (JSONArray)this.storages.get("storages");

        int clue_index = 0;
        for (Object obj : storageArray) {
            JSONObject storage = (JSONObject) obj;

            // JWE client for Storage Server.
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(storage.get("key").toString());
            JweClient client = new JweClient(storage.get("target").toString(), jwk.getKey());

            // Set payload.
            JwtClaims claims = new JwtClaims();
            claims.setStringClaim("type", "STORE_REQUEST");
            claims.setIssuedAtToNow();
            claims.setStringClaim("vID", this.storages.get("vID").toString());
            claims.setClaim("clue", clues[clue_index]);
            String payload = claims.toJson();
            String response = client.sendMessage(payload);
            System.out.println("payload: " + payload);
            System.out.println("response: " + response);

            clue_index++;
        }
    }

    public String[] clueRequest() throws JoseException, IOException, InterruptedException, ParseException {
        System.out.println("\n\n[ clueRequest Run... ]");

        JSONArray storageArray = (JSONArray)this.storages.get("storages");

        List<String> clues = new ArrayList<String>();
        for (Object obj : storageArray) {
            JSONObject storage = (JSONObject) obj;
            System.out.println("Storage: " + storage.toString());

            // JWE client for Storage Server.
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(storage.get("key").toString());
            JweClient client = new JweClient(storage.get("target").toString(), jwk.getKey());

            // Set payload.
            JwtClaims claims = new JwtClaims();
            claims.setStringClaim("type", "CLUE_REQUEST");
            claims.setIssuedAtToNow();
            claims.setStringClaim("vID", this.storages.get("vID").toString());
            String payload = claims.toJson();
            String response = client.sendMessage(payload);
            System.out.println("response: " + response);

            JSONParser parser = new JSONParser();
            JSONObject storageClue = (JSONObject) parser.parse(response);

            clues.add(storageClue.get("clue").toString());
        }
        return clues.toArray(new String[0]);
    }

    public String restoreData(String[] clues) {
        System.out.println("\n\n[ restoreData Run... ]");

        Clue clue = new Clue();
        int storageNumber = 3;
        int threshold = 2;

        String reconstructedStr = new String(clue.reconstruct(storageNumber, threshold, clues), StandardCharsets.UTF_8);
        System.out.println("reconstructedStr: " + reconstructedStr);

        return reconstructedStr;
    }

    public void runAllSequence() throws Exception {
        this.jweLowLevelSample();

        String secret = "Sample Secret Data";
        this.backupRequest();
        this.issueVid();
        String[] clues = this.makeClue(secret);
        this.tokenRequest();
        this.storeClue(clues);
        String[] cluesFromStorage = this.clueRequest();
        if (!Arrays.equals(clues, cluesFromStorage)) {
            System.out.println("clueRequest Fail!");
        }
        String secretFromStorage = this.restoreData(cluesFromStorage);
        if (!secret.equals(secretFromStorage)) {
            System.out.println("restoreData Fail!");
        }
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
