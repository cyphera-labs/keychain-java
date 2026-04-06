package dev.cyphera.keychain;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AwsKmsProviderTest {

    private static final byte[] FAKE_PLAINTEXT = new byte[32];
    private static final String KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/test";

    static {
        Arrays.fill(FAKE_PLAINTEXT, (byte) 0xaa);
    }

    private KmsClient mockClient() {
        KmsClient client = mock(KmsClient.class);
        GenerateDataKeyResponse resp = GenerateDataKeyResponse.builder()
                .plaintext(SdkBytes.fromByteArray(FAKE_PLAINTEXT))
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[64]))
                .keyId(KEY_ID)
                .build();
        when(client.generateDataKey(any(GenerateDataKeyRequest.class))).thenReturn(resp);
        return client;
    }

    @Test
    void resolve_returnsActiveRecord() throws Exception {
        var provider = new AwsKmsProvider(KEY_ID, mockClient());
        KeyRecord rec = provider.resolve("customer-primary");
        assertEquals("customer-primary", rec.ref());
        assertEquals(1, rec.version());
        assertEquals(Status.ACTIVE, rec.status());
        assertArrayEquals(FAKE_PLAINTEXT, rec.material());
    }

    @Test
    void resolve_algorithmIsAes256() throws Exception {
        var provider = new AwsKmsProvider(KEY_ID, mockClient());
        assertEquals("aes256", provider.resolve("k").algorithm());
    }

    @Test
    void resolve_cachesResult() throws Exception {
        KmsClient client = mockClient();
        var provider = new AwsKmsProvider(KEY_ID, client);
        provider.resolve("k");
        provider.resolve("k");
        verify(client, times(1)).generateDataKey(any(GenerateDataKeyRequest.class));
    }

    @Test
    void resolve_differentRefsSeparateCalls() throws Exception {
        KmsClient client = mockClient();
        var provider = new AwsKmsProvider(KEY_ID, client);
        provider.resolve("key-a");
        provider.resolve("key-b");
        verify(client, times(2)).generateDataKey(any(GenerateDataKeyRequest.class));
    }

    @Test
    void resolve_sdkException_throwsKeyNotFoundException() {
        KmsClient client = mock(KmsClient.class);
        when(client.generateDataKey(any(GenerateDataKeyRequest.class)))
                .thenThrow(KmsException.builder().message("not found").build());
        var provider = new AwsKmsProvider(KEY_ID, client);
        assertThrows(KeyNotFoundException.class, () -> provider.resolve("bad-ref"));
    }

    @Test
    void resolveVersion_version1_resolves() throws Exception {
        var provider = new AwsKmsProvider(KEY_ID, mockClient());
        assertEquals(1, provider.resolveVersion("k", 1).version());
    }

    @Test
    void resolveVersion_otherVersion_throwsKeyNotFoundException() {
        var provider = new AwsKmsProvider(KEY_ID, mockClient());
        assertThrows(KeyNotFoundException.class, () -> provider.resolveVersion("k", 2));
    }
}
