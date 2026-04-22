package io.cyphera.keychain;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
@EnabledIfEnvironmentVariable(named = "VAULT_ADDR", matches = ".+")
class VaultIntegrationTest {

    private static final String MATERIAL_HEX = "aabbccdd".repeat(8);

    @Test
    void resolve_returnsActiveRecord_againstVaultDev() throws Exception {
        String addr = System.getenv("VAULT_ADDR");
        String token = System.getenv().containsKey("VAULT_TOKEN")
                ? System.getenv("VAULT_TOKEN") : "root";

        // Write secret via Vault HTTP API
        String body = String.format(
                "{\"data\":{\"version\":\"1\",\"status\":\"active\",\"algorithm\":\"adf1\",\"material\":\"%s\"}}",
                MATERIAL_HEX);
        URL url = new URL(addr + "/v1/secret/data/integ-primary");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("X-Vault-Token", token);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes("UTF-8"));
        }
        conn.getResponseCode();
        conn.disconnect();

        VaultProvider provider = new VaultProvider(addr, token);
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
