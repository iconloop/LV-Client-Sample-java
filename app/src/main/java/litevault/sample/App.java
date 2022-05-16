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
import java.util.Random;


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
        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES);
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
        // LITE VAULT testbed is currently running only 3 storage servers. Threshold must be greater than or equal to 2.
        return this.makeClue(data, 3, 2);
    }

    public String[] makeClue(String data, int storageNumber, int threshold) throws InvalidCipherTextException {
        System.out.println("\n\n[ makeClue Run... ]");

        // Clue clue = new Clue(this.storages.get("recovery_key").toString());
        // LITE VAULT 에서는 App 에서 생성한 임의의 동일한 recovery_key 를 사용 한다.
        Clue clue = new Clue("6ffda2012460a0bd2f61f133b747ed6a");
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

    public void storeClue(String[] clues, String tag) throws JoseException, IOException, InterruptedException {
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
            claims.setStringClaim("token", storage.get("token").toString());
            claims.setStringClaim("tag", tag);
            claims.setClaim("clue", clues[clue_index]);
            String payload = claims.toJson();
            String response = client.sendMessage(payload);
            System.out.println("payload: " + payload);
            System.out.println("response: " + response);

            clue_index++;
        }
    }

    public String[] clueRequest(String tag) throws JoseException, IOException, InterruptedException, ParseException {
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
            claims.setStringClaim("token", storage.get("token").toString());
            claims.setStringClaim("tag", tag);
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
        // LITE VAULT testbed is currently running only 3 storage servers. Threshold must be greater than or equal to 2.
        return this.restoreData(clues, 3, 2);
    }

    public String restoreData(String[] clues, int storageNumber, int threshold) {
        System.out.println("\n\n[ restoreData Run... ]");

        // Clue clue = new Clue(this.storages.get("recovery_key").toString());
        // LITE VAULT 에서는 App 에서 생성한 임의의 동일한 recovery_key 를 사용 한다.
        Clue clue = new Clue("6ffda2012460a0bd2f61f133b747ed6a");
        String reconstructedStr = new String(clue.reconstruct(storageNumber, threshold, clues), StandardCharsets.UTF_8);
        System.out.println("reconstructedStr: " + reconstructedStr);

        return reconstructedStr;
    }

    public void runAllSequence() throws Exception {
        this.jweLowLevelSample();

        // clue 로 분해할 원본 secret
        String secret = "Sample Secret Data";

        // VPR
        this.backupRequest();

        // VID
        this.issueVid();

        // secret 을 clues 로 분해 한다. clue 는 LV-Manager 로 부터 받은 recovery-key 로 추가 암호화 진행을 하므로
        // secret 의 clues 분해는 VID 이후에 진행 한다.
        String[] clues = this.makeClue(secret);

        // TOKEN
        this.tokenRequest();

        // STORE with tag
        this.storeClue(clues, "tag_000");

        // READ with tag
        String[] cluesFromStorage = this.clueRequest("tag_000");
        if (!Arrays.equals(clues, cluesFromStorage)) {
            System.out.println("clueRequest Fail!");
        }

        // clue 를 원본 secret 으로 복원 한다.
        String secretFromStorage = this.restoreData(cluesFromStorage);
        if (!secret.equals(secretFromStorage)) {
            System.out.println("restoreData Fail!");
        }

        System.out.println("\n\n[ End of runAllSequence ]");
        System.out.println("Original secret: " + secret);
        System.out.println("Restored secret: " + secretFromStorage);
    }

    public void multiTagSample() throws Exception {
        // tag 별 원본 secret
        String secret_tag1 = "Secret Data 123";
        String secret_tag2 = "Sample Secret Data ABC";
        String secret_tag3 = "Data SECRET";

        // VPR, VID, TOKEN and STORE for tag1
        this.backupRequest();
        this.issueVid();
        String[] clues1 = this.makeClue(secret_tag1);
        this.tokenRequest();
        this.storeClue(clues1, "tag_1");

        // VPR, VID, TOKEN and STORE for tag2
        this.backupRequest();
        this.issueVid();
        String[] clues2 = this.makeClue(secret_tag2);
        this.tokenRequest();
        this.storeClue(clues2, "tag_2");

        // VPR, VID, TOKEN and STORE for tag3
        this.backupRequest();
        this.issueVid();
        String[] clues3 = this.makeClue(secret_tag3);
        this.tokenRequest();
        this.storeClue(clues3, "tag_3");


        // VPR, VID, TOKEN and READ with tag(random 1 to 3)
        this.backupRequest();
        this.issueVid();
        this.tokenRequest();
        int random_tag_num = new Random().nextInt(2) + 1;
        String random_tag = "tag_" + random_tag_num;
        // READ with tag
        String[] cluesFromStorage = this.clueRequest(random_tag);
        // clue 를 원본 secret 으로 복원 한다.
        String secretFromStorage = this.restoreData(cluesFromStorage);

        System.out.println("\n\n[ Multi Tag Sample ]");
        System.out.println("Original secret tag_1: " + secret_tag1);
        System.out.println("Original secret tag_2: " + secret_tag2);
        System.out.println("Original secret tag_3: " + secret_tag3);

        System.out.println("Random Tag: " + random_tag);
        System.out.println("Restored secret: " + secretFromStorage);
    }

    public void MakeClueWithStorageNumber() throws Exception {
        // 테스트베드의 스토리지 서버가 3개뿐이므로 clue 를 5개로 쪼개고 임계값을 3으로 설정하여
        // 임계값 내의 clue 만 저장한 다음 복원하는 테스트입니다.

        String secret = "Secret Data for 5 clues and 3 threshold!";

        // VPR, VID, TOKEN and Make clues with storageNumber = 5, threshold = 3
        this.backupRequest();
        this.issueVid();
        String[] clues = this.makeClue(secret, 5, 3);
        this.tokenRequest();
        // storageArray 크기인 3까지만 저장이 된다. 나머지 clue 는 저장되지 않지만 임계점 내이므로 복원이 가능하다.
        this.storeClue(clues, "tag_storageNumTest");

        // READ with tag
        String[] cluesFromStorage = this.clueRequest("tag_storageNumTest");
        // clue 를 원본 secret 으로 복원 한다.
        String secretFromStorage = this.restoreData(cluesFromStorage, 5, 3);

        System.out.println("\n\n[ Make Clue With StorageNumber 5 but Threshold 3]");
        System.out.println("Clues length is " + clues.length);
        System.out.println("But cluesFromStorage length is " + cluesFromStorage.length);
        System.out.println("And Restored secret: " + secretFromStorage);
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
        samples.multiTagSample();
        samples.MakeClueWithStorageNumber();
    }

    public String getGreeting() {
        return "Hello LITE VAULT!";
    }
}
