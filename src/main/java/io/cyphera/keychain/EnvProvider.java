package io.cyphera.keychain;

import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * {@link KeyProvider} that resolves keys from environment variables.
 *
 * <p>For a key ref {@code "customer-primary"} and prefix {@code "CYPHERA"}, the provider
 * looks for:</p>
 * <ul>
 *   <li>{@code CYPHERA_CUSTOMER_PRIMARY_KEY} — required; hex or base64-encoded key material</li>
 *   <li>{@code CYPHERA_CUSTOMER_PRIMARY_TWEAK} — optional; hex or base64-encoded tweak</li>
 * </ul>
 *
 * <p>All resolved keys are version 1 and {@link Status#ACTIVE}.</p>
 *
 * <p>The algorithm field is set to {@code "env"} since the algorithm is not encoded in the
 * environment variable name. Callers who need a specific algorithm should use
 * {@link MemoryProvider} or {@link FileProvider} instead.</p>
 */
public final class EnvProvider implements KeyProvider {

    private final String prefix;
    private final Function<String, String> envLookup;

    /**
     * Constructs an {@code EnvProvider} that reads from {@link System#getenv(String)}.
     *
     * @param prefix environment variable prefix (e.g. {@code "CYPHERA"})
     */
    public EnvProvider(String prefix) {
        this(prefix, System::getenv);
    }

    /**
     * Package-private constructor for testing — allows injecting a custom environment lookup.
     *
     * @param prefix    environment variable prefix
     * @param envLookup function mapping variable name to value; return {@code null} if absent
     */
    EnvProvider(String prefix, Function<String, String> envLookup) {
        this.prefix = prefix.toUpperCase();
        this.envLookup = envLookup;
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        String normalizedRef = normalizeRef(ref);
        String keyVar = prefix + "_" + normalizedRef + "_KEY";
        String rawKey = envLookup.apply(keyVar);
        if (rawKey == null || rawKey.trim().isEmpty()) {
            throw new KeyNotFoundException(
                    "Environment variable not found: " + keyVar);
        }

        byte[] material = decodeBytes(rawKey, keyVar);

        String tweakVar = prefix + "_" + normalizedRef + "_TWEAK";
        String rawTweak = envLookup.apply(tweakVar);
        byte[] tweak = null;
        if (rawTweak != null && !rawTweak.trim().isEmpty()) {
            tweak = decodeBytes(rawTweak, tweakVar);
        }

        return new KeyRecord(ref, 1, Status.ACTIVE, "env", material, tweak,
                Collections.<String, String>emptyMap(), Instant.now());
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        if (version != 1) {
            throw new KeyNotFoundException(
                    "EnvProvider only supports version 1; requested version " + version
                            + " for ref: " + ref);
        }
        return resolve(ref);
    }

    // --- private helpers ---

    /**
     * Normalizes a ref for use in an env var name.
     * Uppercases the ref and replaces {@code -} and {@code .} with {@code _}.
     */
    private static String normalizeRef(String ref) {
        return ref.toUpperCase().replace('-', '_').replace('.', '_');
    }

    /**
     * Decodes a hex string to bytes.
     *
     * @param hex hex-encoded string
     * @return decoded bytes
     */
    static byte[] decodeHex(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("odd length");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi == -1 || lo == -1) {
                throw new IllegalArgumentException("invalid hex at index " + i);
            }
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    /**
     * Decodes a hex or base64 string to bytes.
     *
     * <p>Tries hex first, then standard base64, then URL-safe base64.</p>
     *
     * @param value   encoded string
     * @param varName variable name for error messages
     * @return decoded bytes
     * @throws KeyProviderException if the value cannot be decoded
     */
    static byte[] decodeBytes(String value, String varName) throws KeyProviderException {
        // Try hex first
        try {
            return decodeHex(value);
        } catch (Exception ignored) {
            // not hex
        }

        // Try standard base64
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException ignored) {
            // not standard base64
        }

        // Try URL-safe base64
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new KeyProviderException(
                    "Cannot decode value of " + varName + " as hex or base64", e);
        }
    }
}
