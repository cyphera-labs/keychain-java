package dev.cyphera.keychain;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
@EnabledIfEnvironmentVariable(named = "VAULT_ADDR", matches = ".+")
class VaultIntegrationTest {

    private static final String MATERIAL_HEX = "aabbccdd".repeat(8);

    @Test
    void resolve_returnsActiveRecord_againstVaultDev() throws Exception {
        String addr = System.getenv("VAULT_ADDR");
        String token = System.getenv().getOrDefault("VAULT_TOKEN", "root");

        // Write secret via Vault HTTP API
        String body = String.format(
                "{\"data\":{\"version\":\"1\",\"status\":\"active\",\"algorithm\":\"adf1\",\"material\":\"%s\"}}",
                MATERIAL_HEX);
        HttpClient http = HttpClient.newHttpClient();
        http.send(HttpRequest.newBuilder()
                .uri(URI.create(addr + "/v1/secret/data/integ-primary"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());

        var provider = new VaultProvider(addr, token);
        KeyRecord rec = provider.resolve("integ-primary");
        assertEquals(Status.ACTIVE, rec.status());
        assertArrayEquals(hexToBytes(MATERIAL_HEX), rec.material());
    }

    private static byte[] hexToBytes(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
