package iconloop.lab.util;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;


public class JweClient {
    private final URI serverUri;
    private final Key serverPubKey;

    private JsonWebEncryption getSenderJwe(String payload) {
        JsonWebEncryption senderJwe = new JsonWebEncryption();
        senderJwe.setKey(this.serverPubKey);
        senderJwe.setPayload(payload);
        senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
        senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM);
        return senderJwe;
    }

    private String sendHttpRequest(String message) throws IOException, InterruptedException {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(this.serverUri)
                .POST(HttpRequest.BodyPublishers.noBody())
                .header("Authorization", message)
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        return response.body().replaceAll("\"", "");
    }

    public String sendMessage(String payload) throws JoseException, IOException, InterruptedException {
        JsonWebEncryption senderJwe = this.getSenderJwe(payload);
        String compactSerialization = senderJwe.getCompactSerialization();
        Key cek = new SecretKeySpec(senderJwe.getContentEncryptionKey(), "AESWrap");
        String httpResponse = this.sendHttpRequest(compactSerialization);

        JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setKey(cek);
        receiverJwe.setCompactSerialization(httpResponse);

        return receiverJwe.getPlaintextString();
    }

    public JweClient(String serverUri, Key serverPubKey) {
        this.serverUri = URI.create("http://" + serverUri + "/vault");
        this.serverPubKey = serverPubKey;
    }
}
