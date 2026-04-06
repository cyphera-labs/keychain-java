package dev.cyphera.keychain;

import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Key provider backed by GCP Cloud KMS.
 *
 * <p>Generates a random AES-256 data key, wraps it via GCP KMS encrypt, and
 * caches the plaintext for the lifetime of the provider.
 */
public final class GcpKmsProvider implements KeyProvider {

    private final String keyName;
    private final KeyManagementServiceClient client;
    private final Map<String, byte[]> plaintextCache = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * @param keyName Fully-qualified KMS key name:
     *                {@code projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}}
     */
    public GcpKmsProvider(String keyName) throws IOException {
        this(keyName, KeyManagementServiceClient.create());
    }

    /** Package-private constructor for testing. */
    GcpKmsProvider(String keyName, KeyManagementServiceClient client) {
        this.keyName = keyName;
        this.client = client;
    }

    private byte[] wrapNewKey(String ref) throws KeyNotFoundException {
        byte[] plaintext = new byte[32];
        RANDOM.nextBytes(plaintext);
        try {
            client.encrypt(EncryptRequest.newBuilder()
                    .setName(keyName)
                    .setPlaintext(ByteString.copyFrom(plaintext))
                    .setAdditionalAuthenticatedData(ByteString.copyFromUtf8(ref))
                    .build());
        } catch (Exception e) {
            throw new KeyNotFoundException("Key not found: " + ref, e);
        }
        return plaintext;
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        byte[] material = plaintextCache.get(ref);
        if (material == null) {
            material = wrapNewKey(ref);
            plaintextCache.put(ref, material);
        }
        return new KeyRecord(ref, 1, Status.ACTIVE, "aes256", material, null, Map.of(), null);
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        if (version != 1) throw new KeyNotFoundException("Key not found: " + ref + " version " + version);
        return resolve(ref);
    }
}
