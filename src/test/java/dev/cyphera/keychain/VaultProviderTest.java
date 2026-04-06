package dev.cyphera.keychain;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class VaultProviderTest {

    private static final String MATERIAL_HEX = "aa".repeat(32);
    private static final byte[] MATERIAL_BYTES;

    static {
        MATERIAL_BYTES = new byte[32];
        for (int i = 0; i < 32; i++) MATERIAL_BYTES[i] = (byte) 0xaa;
    }

    private static Vault mockVault(Map<String, String> data, int httpStatus) throws Exception {
        RestResponse restResponse = mock(RestResponse.class);
        when(restResponse.getStatus()).thenReturn(httpStatus);

        LogicalResponse response = mock(LogicalResponse.class);
        when(response.getRestResponse()).thenReturn(restResponse);
        when(response.getData()).thenReturn(data);

        Logical logical = mock(Logical.class);
        when(logical.read(anyString())).thenReturn(response);

        Vault vault = mock(Vault.class);
        when(vault.logical()).thenReturn(logical);
        return vault;
    }

    @Test
    void resolve_returnsActiveRecord() throws Exception {
        Vault vault = mockVault(Map.of(
                "version", "1",
                "status", "active",
                "algorithm", "adf1",
                "material", MATERIAL_HEX
        ), 200);
        var provider = new VaultProvider(vault, "secret");
        KeyRecord rec = provider.resolve("customer-primary");
        assertEquals("customer-primary", rec.ref());
        assertEquals(1, rec.version());
        assertEquals(Status.ACTIVE, rec.status());
        assertArrayEquals(MATERIAL_BYTES, rec.material());
    }

    @Test
    void resolve_noActiveKey_throwsNoActiveKeyException() throws Exception {
        Vault vault = mockVault(Map.of(
                "version", "1",
                "status", "disabled",
                "algorithm", "adf1",
                "material", MATERIAL_HEX
        ), 200);
        var provider = new VaultProvider(vault, "secret");
        assertThrows(NoActiveKeyException.class, () -> provider.resolve("k"));
    }

    @Test
    void resolve_notFound_throwsKeyNotFoundException() throws Exception {
        Vault vault = mockVault(Map.of(), 404);
        var provider = new VaultProvider(vault, "secret");
        assertThrows(KeyNotFoundException.class, () -> provider.resolve("missing"));
    }

    @Test
    void resolveVersion_disabled_throwsKeyDisabledException() throws Exception {
        Vault vault = mockVault(Map.of(
                "version", "1",
                "status", "disabled",
                "material", MATERIAL_HEX
        ), 200);
        var provider = new VaultProvider(vault, "secret");
        assertThrows(KeyDisabledException.class, () -> provider.resolveVersion("k", 1));
    }

    @Test
    void resolveVersion_wrongVersion_throwsKeyNotFoundException() throws Exception {
        Vault vault = mockVault(Map.of(
                "version", "1",
                "status", "active",
                "material", MATERIAL_HEX
        ), 200);
        var provider = new VaultProvider(vault, "secret");
        assertThrows(KeyNotFoundException.class, () -> provider.resolveVersion("k", 99));
    }
}
