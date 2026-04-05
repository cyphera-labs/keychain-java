package dev.cyphera.keychain;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EnvProviderTest {

    private static final byte[] KEY_BYTES = new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    private static final byte[] TWEAK_BYTES = new byte[]{0x11, 0x12, 0x13, 0x14};

    /** Builds a provider backed by a fixed env map. */
    private static EnvProvider providerWithEnv(Map<String, String> env) {
        return new EnvProvider("CYPHERA", env::get);
    }

    @Test
    void resolve_withHexEncodedKey() throws KeyProviderException {
        String hexKey = HexFormat.of().formatHex(KEY_BYTES);
        var env = Map.of("CYPHERA_CUSTOMER_PRIMARY_KEY", hexKey);
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolve("customer-primary");

        assertEquals("customer-primary", record.ref());
        assertEquals(1, record.version());
        assertEquals(Status.ACTIVE, record.status());
        assertArrayEquals(KEY_BYTES, record.material());
        assertNull(record.tweak());
    }

    @Test
    void resolve_withBase64EncodedKey() throws KeyProviderException {
        String b64Key = Base64.getEncoder().encodeToString(KEY_BYTES);
        var env = Map.of("CYPHERA_CUSTOMER_PRIMARY_KEY", b64Key);
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolve("customer-primary");

        assertArrayEquals(KEY_BYTES, record.material());
    }

    @Test
    void resolve_withUrlSafeBase64EncodedKey() throws KeyProviderException {
        String b64Key = Base64.getUrlEncoder().encodeToString(KEY_BYTES);
        var env = Map.of("CYPHERA_CUSTOMER_PRIMARY_KEY", b64Key);
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolve("customer-primary");

        assertArrayEquals(KEY_BYTES, record.material());
    }

    @Test
    void resolve_withTweakVar() throws KeyProviderException {
        String hexKey = HexFormat.of().formatHex(KEY_BYTES);
        String hexTweak = HexFormat.of().formatHex(TWEAK_BYTES);
        var env = Map.of(
                "CYPHERA_CUSTOMER_PRIMARY_KEY", hexKey,
                "CYPHERA_CUSTOMER_PRIMARY_TWEAK", hexTweak
        );
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolve("customer-primary");

        assertArrayEquals(KEY_BYTES, record.material());
        assertArrayEquals(TWEAK_BYTES, record.tweak());
    }

    @Test
    void resolve_missingKey_throwsKeyNotFoundException() {
        var provider = providerWithEnv(Map.of());
        assertThrows(KeyNotFoundException.class,
                () -> provider.resolve("customer-primary"));
    }

    @Test
    void resolveVersion_version1_works() throws KeyProviderException {
        String hexKey = HexFormat.of().formatHex(KEY_BYTES);
        var env = Map.of("CYPHERA_CUSTOMER_PRIMARY_KEY", hexKey);
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolveVersion("customer-primary", 1);

        assertEquals(1, record.version());
        assertArrayEquals(KEY_BYTES, record.material());
    }

    @Test
    void resolveVersion_version2_throwsKeyNotFoundException() {
        String hexKey = HexFormat.of().formatHex(KEY_BYTES);
        var env = Map.of("CYPHERA_CUSTOMER_PRIMARY_KEY", hexKey);
        var provider = providerWithEnv(env);

        assertThrows(KeyNotFoundException.class,
                () -> provider.resolveVersion("customer-primary", 2));
    }

    @Test
    void resolve_refWithDotsNormalized() throws KeyProviderException {
        // ref "my.service.key" should map to MY_SERVICE_KEY
        String hexKey = HexFormat.of().formatHex(KEY_BYTES);
        var env = Map.of("CYPHERA_MY_SERVICE_KEY_KEY", hexKey);
        var provider = providerWithEnv(env);

        KeyRecord record = provider.resolve("my.service.key");
        assertArrayEquals(KEY_BYTES, record.material());
    }

    @Test
    void decodeBytes_invalidValue_throwsKeyProviderException() {
        assertThrows(KeyProviderException.class,
                () -> EnvProvider.decodeBytes("!!!not-valid!!!", "TEST_VAR"));
    }
}
