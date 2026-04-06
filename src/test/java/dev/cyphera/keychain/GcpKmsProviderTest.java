package dev.cyphera.keychain;

import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class GcpKmsProviderTest {

    private static final String KEY_NAME =
            "projects/test/locations/global/keyRings/r/cryptoKeys/k";

    private KeyManagementServiceClient mockClient() {
        KeyManagementServiceClient client = mock(KeyManagementServiceClient.class);
        EncryptResponse resp = EncryptResponse.newBuilder()
                .setCiphertext(ByteString.copyFrom(new byte[64]))
                .build();
        when(client.encrypt(any(EncryptRequest.class))).thenReturn(resp);
        return client;
    }

    @Test
    void resolve_returnsActiveRecord() throws Exception {
        var provider = new GcpKmsProvider(KEY_NAME, mockClient());
        KeyRecord rec = provider.resolve("customer-primary");
        assertEquals("customer-primary", rec.ref());
        assertEquals(1, rec.version());
        assertEquals(Status.ACTIVE, rec.status());
        assertEquals(32, rec.material().length);
    }

    @Test
    void resolve_cachesResult() throws Exception {
        var client = mockClient();
        var provider = new GcpKmsProvider(KEY_NAME, client);
        byte[] m1 = provider.resolve("k").material();
        byte[] m2 = provider.resolve("k").material();
        assertArrayEquals(m1, m2);
        verify(client, times(1)).encrypt(any(EncryptRequest.class));
    }

    @Test
    void resolve_encryptFails_throwsKeyNotFoundException() {
        var client = mock(KeyManagementServiceClient.class);
        when(client.encrypt(any(EncryptRequest.class))).thenThrow(new RuntimeException("API error"));
        var provider = new GcpKmsProvider(KEY_NAME, client);
        assertThrows(KeyNotFoundException.class, () -> provider.resolve("bad-ref"));
    }

    @Test
    void resolveVersion_version1_resolves() throws Exception {
        var provider = new GcpKmsProvider(KEY_NAME, mockClient());
        assertEquals(1, provider.resolveVersion("k", 1).version());
    }

    @Test
    void resolveVersion_otherVersion_throws() {
        var provider = new GcpKmsProvider(KEY_NAME, mockClient());
        assertThrows(KeyNotFoundException.class, () -> provider.resolveVersion("k", 2));
    }
}
