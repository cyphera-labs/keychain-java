package io.cyphera.keychain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FileProviderTest {

    @TempDir
    Path tempDir;

    private static final byte[] KEY_BYTES = new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };

    private static String encodeHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private Path writeJson(String content) throws IOException {
        Path file = tempDir.resolve("keys.json");
        Files.write(file, content.getBytes("UTF-8"));
        return file;
    }

    @Test
    void resolve_activeKey_returnsRecord() throws Exception {
        String hex = encodeHex(KEY_BYTES);
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"customer-primary\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        KeyRecord record = provider.resolve("customer-primary");

        assertEquals("customer-primary", record.ref());
        assertEquals(1, record.version());
        assertEquals(Status.ACTIVE, record.status());
        assertEquals("adf1", record.algorithm());
        assertArrayEquals(KEY_BYTES, record.material());
        assertNull(record.tweak());
    }

    @Test
    void resolveVersion_returnsCorrectVersion() throws Exception {
        String hex = encodeHex(KEY_BYTES);
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"deprecated\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 2,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        KeyRecord v1 = provider.resolveVersion("my-key", 1);
        KeyRecord v2 = provider.resolveVersion("my-key", 2);

        assertEquals(1, v1.version());
        assertEquals(Status.DEPRECATED, v1.status());
        assertEquals(2, v2.version());
        assertEquals(Status.ACTIVE, v2.status());
    }

    @Test
    void resolve_highestActiveVersion_whenMultipleExist() throws Exception {
        String hex = encodeHex(KEY_BYTES);
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 2,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        KeyRecord record = provider.resolve("my-key");
        assertEquals(2, record.version());
    }

    @Test
    void resolve_missingRef_throwsKeyNotFoundException() throws Exception {
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"other-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"0102030405060708090a0b0c0d0e0f10\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        assertThrows(KeyNotFoundException.class,
                () -> provider.resolve("missing-key"));
    }

    @Test
    void resolveVersion_disabledKey_throwsKeyDisabledException() throws Exception {
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"disabled\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"0102030405060708090a0b0c0d0e0f10\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        assertThrows(KeyDisabledException.class,
                () -> provider.resolveVersion("my-key", 1));
    }

    @Test
    void resolve_noActiveVersion_throwsNoActiveKeyException() throws Exception {
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"deprecated\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"0102030405060708090a0b0c0d0e0f10\"\n"
                + "    },\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 2,\n"
                + "      \"status\": \"disabled\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"0102030405060708090a0b0c0d0e0f10\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        assertThrows(NoActiveKeyException.class,
                () -> provider.resolve("my-key"));
    }

    @Test
    void resolve_withTweak_populatesTweakField() throws Exception {
        String hex = encodeHex(KEY_BYTES);
        byte[] tweakBytes = new byte[]{0x11, 0x12, 0x13, 0x14};
        String tweakHex = encodeHex(tweakBytes);
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\",\n"
                + "      \"tweak\": \"" + tweakHex + "\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        KeyRecord record = provider.resolve("my-key");

        assertNotNull(record.tweak());
        assertArrayEquals(tweakBytes, record.tweak());
    }

    @Test
    void resolve_withMetadataAndCreatedAt() throws Exception {
        String hex = encodeHex(KEY_BYTES);
        Path file = writeJson(
                "{\n"
                + "  \"keys\": [\n"
                + "    {\n"
                + "      \"ref\": \"my-key\",\n"
                + "      \"version\": 1,\n"
                + "      \"status\": \"active\",\n"
                + "      \"algorithm\": \"adf1\",\n"
                + "      \"material\": \"" + hex + "\",\n"
                + "      \"metadata\": { \"owner\": \"team-a\" },\n"
                + "      \"created_at\": \"2024-01-01T00:00:00Z\"\n"
                + "    }\n"
                + "  ]\n"
                + "}\n");

        FileProvider provider = new FileProvider(file);
        KeyRecord record = provider.resolve("my-key");

        assertEquals("team-a", record.metadata().get("owner"));
        assertNotNull(record.createdAt());
        assertEquals("2024-01-01T00:00:00Z", record.createdAt().toString());
    }

    @Test
    void constructor_invalidFile_throwsKeyProviderException() {
        Path badPath = tempDir.resolve("nonexistent.json");
        assertThrows(KeyProviderException.class,
                () -> new FileProvider(badPath));
    }
}
