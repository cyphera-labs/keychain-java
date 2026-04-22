package io.cyphera.keychain;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.models.KeyVaultKey;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Key provider backed by Azure Key Vault.
 *
 * <p>Generates a random AES-256 data key, wraps it with an Azure Key Vault
 * RSA key (RSA-OAEP), and caches the plaintext.
 */
public final class AzureKvProvider implements KeyProvider {

    private final String keyName;
    private final KeyClient keyClient;
    private final TokenCredential credential;
    private final Map<String, byte[]> plaintextCache = new ConcurrentHashMap<>();
    private static final SecureRandom RANDOM = new SecureRandom();

    public AzureKvProvider(String vaultUrl, String keyName) {
        this(vaultUrl, keyName, new DefaultAzureCredentialBuilder().build());
    }

    public AzureKvProvider(String vaultUrl, String keyName, TokenCredential credential) {
        this.keyName = keyName;
        this.credential = credential;
        this.keyClient = new KeyClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .buildClient();
    }

    /** Package-private constructor for testing. */
    AzureKvProvider(KeyClient keyClient, String keyName, TokenCredential credential) {
        this.keyClient = keyClient;
        this.keyName = keyName;
        this.credential = credential;
    }

    private byte[] wrapNewKey(String ref) throws KeyNotFoundException {
        byte[] plaintext = new byte[32];
        RANDOM.nextBytes(plaintext);
        try {
            KeyVaultKey key = keyClient.getKey(keyName);
            CryptographyClient cryptoClient = new CryptographyClientBuilder()
                    .keyIdentifier(key.getId())
                    .credential(credential)
                    .buildClient();
            cryptoClient.wrapKey(KeyWrapAlgorithm.RSA_OAEP, plaintext);
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
        return new KeyRecord(ref, 1, Status.ACTIVE, "aes256", material, null,
                Collections.<String, String>emptyMap(), null);
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        if (version != 1) throw new KeyNotFoundException("Key not found: " + ref + " version " + version);
        return resolve(ref);
    }
}
