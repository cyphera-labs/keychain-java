package io.cyphera.keychain;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class MemoryProviderTest {

    private static final byte[] MATERIAL = new byte[]{1, 2, 3, 4, 5, 6, 7, 8,
            9, 10, 11, 12, 13, 14, 15, 16};

    private static KeyRecord record(String ref, int version, Status status) {
        return new KeyRecord(ref, version, status, "adf1", MATERIAL, null,
                Collections.<String, String>emptyMap(), null);
    }

    @Test
    void resolve_returnsHighestActiveVersion() throws KeyProviderException {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.DEPRECATED),
                record("my-key", 2, Status.ACTIVE),
                record("my-key", 3, Status.ACTIVE)
        );
        KeyRecord result = provider.resolve("my-key");
        assertEquals(3, result.version());
        assertEquals(Status.ACTIVE, result.status());
    }

    @Test
    void resolveVersion_returnsSpecificVersion() throws KeyProviderException {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.DEPRECATED),
                record("my-key", 2, Status.ACTIVE)
        );
        KeyRecord result = provider.resolveVersion("my-key", 1);
        assertEquals(1, result.version());
        assertEquals(Status.DEPRECATED, result.status());
    }

    @Test
    void resolveVersion_onDisabledKey_throwsKeyDisabledException() {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.DISABLED)
        );
        assertThrows(KeyDisabledException.class,
                () -> provider.resolveVersion("my-key", 1));
    }

    @Test
    void resolveVersion_onUnknownRef_throwsKeyNotFoundException() {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.ACTIVE)
        );
        assertThrows(KeyNotFoundException.class,
                () -> provider.resolveVersion("other-key", 1));
    }

    @Test
    void resolve_withNoActiveVersions_throwsNoActiveKeyException() {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.DEPRECATED),
                record("my-key", 2, Status.DISABLED)
        );
        assertThrows(NoActiveKeyException.class,
                () -> provider.resolve("my-key"));
    }

    @Test
    void resolve_onUnknownRef_throwsKeyNotFoundException() {
        MemoryProvider provider = new MemoryProvider();
        assertThrows(KeyNotFoundException.class,
                () -> provider.resolve("missing-key"));
    }

    @Test
    void add_insertsRecord() throws KeyProviderException {
        MemoryProvider provider = new MemoryProvider();
        provider.add(record("new-key", 1, Status.ACTIVE));
        KeyRecord result = provider.resolve("new-key");
        assertEquals("new-key", result.ref());
        assertEquals(1, result.version());
    }

    @Test
    void add_replacesExistingVersionWithSameNumber() throws KeyProviderException {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.DEPRECATED)
        );
        provider.add(record("my-key", 1, Status.ACTIVE));
        KeyRecord result = provider.resolveVersion("my-key", 1);
        assertEquals(Status.ACTIVE, result.status());
    }

    @Test
    void resolve_skipsDeprecatedAndReturnsActive() throws KeyProviderException {
        MemoryProvider provider = new MemoryProvider(
                record("my-key", 1, Status.ACTIVE),
                record("my-key", 2, Status.DEPRECATED)
        );
        // Version 2 is deprecated, so highest active is version 1
        KeyRecord result = provider.resolve("my-key");
        assertEquals(1, result.version());
    }
}
