package dev.cyphera.keychain;

import com.azure.core.credential.TokenCredential;
import com.azure.security.keyvault.keys.KeyClient;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AzureKvProviderTest {

    private static final String KEY_NAME = "test-rsa-key";

    @Test
    void resolveVersion_otherVersion_throwsKeyNotFoundException() {
        var keyClient = mock(KeyClient.class);
        var cred = mock(TokenCredential.class);
        var provider = new AzureKvProvider(keyClient, KEY_NAME, cred);
        assertThrows(KeyNotFoundException.class, () -> provider.resolveVersion("k", 2));
    }

    @Test
    void resolve_keyClientThrows_throwsKeyNotFoundException() {
        var keyClient = mock(KeyClient.class);
        when(keyClient.getKey(KEY_NAME)).thenThrow(new RuntimeException("not found"));
        var cred = mock(TokenCredential.class);
        var provider = new AzureKvProvider(keyClient, KEY_NAME, cred);
        assertThrows(KeyNotFoundException.class, () -> provider.resolve("bad-ref"));
    }
}
