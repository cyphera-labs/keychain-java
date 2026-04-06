package dev.cyphera.keychain;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Key provider backed by AWS KMS data-key generation.
 *
 * <p>Each resolved ref is backed by an AES-256 data key generated via the
 * configured KMS master key. The plaintext data key is cached in memory for
 * the lifetime of the provider.
 */
public final class AwsKmsProvider implements KeyProvider {

    private final String keyId;
    private final KmsClient kmsClient;
    private final Map<String, KeyRecord> cache = new ConcurrentHashMap<>();

    public AwsKmsProvider(String keyId) {
        this(keyId, KmsClient.create());
    }

    public AwsKmsProvider(String keyId, String region, String endpointUrl) {
        this(keyId, KmsClient.builder()
                .region(Region.of(region))
                .endpointOverride(URI.create(endpointUrl))
                .build());
    }

    /** Package-private constructor for testing with a mock client. */
    AwsKmsProvider(String keyId, KmsClient kmsClient) {
        this.keyId = keyId;
        this.kmsClient = kmsClient;
    }

    private KeyRecord generate(String ref) throws KeyNotFoundException {
        try {
            GenerateDataKeyResponse response = kmsClient.generateDataKey(
                    GenerateDataKeyRequest.builder()
                            .keyId(keyId)
                            .keySpec(DataKeySpec.AES_256)
                            .encryptionContext(Map.of("cyphera:ref", ref))
                            .build());
            byte[] material = response.plaintext().asByteArray();
            return new KeyRecord(ref, 1, Status.ACTIVE, "aes256", material, null, Map.of(), null);
        } catch (KmsException e) {
            throw new KeyNotFoundException("Key not found: " + ref, e);
        }
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        KeyRecord cached = cache.get(ref);
        if (cached != null) return cached;
        KeyRecord record = generate(ref);
        cache.put(ref, record);
        return record;
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        if (version != 1) throw new KeyNotFoundException("Key not found: " + ref + " version " + version);
        return resolve(ref);
    }
}
