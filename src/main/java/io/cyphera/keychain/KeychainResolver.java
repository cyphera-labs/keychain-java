package io.cyphera.keychain;

import java.util.Map;

/**
 * Bridge resolver for Cyphera SDK config-driven key sources.
 * Called by the SDK via reflection when cyphera.json has "source" set to a cloud provider.
 */
public final class KeychainResolver {

    private KeychainResolver() {}

    /**
     * Resolve a key from a cloud provider based on the cyphera.json key config.
     * Returns raw key bytes.
     */
    public static byte[] resolve(String source, Map<String, Object> config) {
        String ref = firstNonNull(
            (String) config.get("ref"),
            (String) config.get("path"),
            (String) config.get("arn"),
            (String) config.get("key"),
            "default"
        );

        try {
            KeyProvider provider = createProvider(source, config);
            KeyRecord record = provider.resolve(ref);
            return record.material();
        } catch (Exception e) {
            throw new RuntimeException("Keychain resolution failed for source '" + source + "': " + e.getMessage(), e);
        }
    }

    private static KeyProvider createProvider(String source, Map<String, Object> config) throws Exception {
        switch (source) {
            case "vault": {
                String addr = firstNonNull((String) config.get("addr"), System.getenv("VAULT_ADDR"), "http://127.0.0.1:8200");
                String token = firstNonNull((String) config.get("token"), System.getenv("VAULT_TOKEN"), "");
                String mount = firstNonNull((String) config.get("mount"), "secret");
                return new VaultProvider(addr, token, mount);
            }
            case "aws-kms": {
                String arn = config.containsKey("arn") ? (String) config.get("arn") : "";
                String region = firstNonNull((String) config.get("region"), System.getenv("AWS_REGION"), "us-east-1");
                String endpoint = (String) config.get("endpoint");
                return endpoint != null ? new AwsKmsProvider(arn, region, endpoint) : new AwsKmsProvider(arn);
            }
            case "gcp-kms": {
                String resource = config.containsKey("resource") ? (String) config.get("resource") : "";
                try {
                    return new GcpKmsProvider(resource);
                } catch (Exception e) {
                    throw new RuntimeException("Failed to create GCP KMS provider: " + e.getMessage(), e);
                }
            }
            case "azure-kv": {
                String vault = config.containsKey("vault") ? (String) config.get("vault") : "";
                String keyName = config.containsKey("key") ? (String) config.get("key") : "";
                return new AzureKvProvider("https://" + vault + ".vault.azure.net", keyName);
            }
            default:
                throw new IllegalArgumentException("Unknown source: " + source);
        }
    }

    private static String firstNonNull(String... values) {
        for (String v : values) {
            if (v != null && !v.isEmpty()) return v;
        }
        return "";
    }
}
