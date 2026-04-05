package dev.cyphera.keychain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * {@link KeyProvider} that loads keys from a JSON file at construction time.
 *
 * <p>The expected file format is:</p>
 * <pre>{@code
 * {
 *   "keys": [
 *     {
 *       "ref": "customer-primary",
 *       "version": 1,
 *       "status": "active",
 *       "algorithm": "adf1",
 *       "material": "<hex or base64>",
 *       "tweak": "<hex or base64>",
 *       "metadata": { "owner": "team-a" },
 *       "created_at": "2024-01-01T00:00:00Z"
 *     }
 *   ]
 * }
 * }</pre>
 *
 * <p>{@code tweak}, {@code metadata}, and {@code created_at} are optional.</p>
 */
public final class FileProvider implements KeyProvider {

    private final Map<String, List<KeyRecord>> store = new HashMap<>();

    /**
     * Constructs a {@code FileProvider} by loading keys from the given file path.
     *
     * @param path path to the JSON key file
     * @throws KeyProviderException if the file cannot be read or parsed
     */
    public FileProvider(String path) throws KeyProviderException {
        this(Path.of(path));
    }

    /**
     * Constructs a {@code FileProvider} by loading keys from the given {@link Path}.
     *
     * @param path path to the JSON key file
     * @throws KeyProviderException if the file cannot be read or parsed
     */
    public FileProvider(Path path) throws KeyProviderException {
        ObjectMapper mapper = new ObjectMapper();
        KeyFile keyFile;
        try {
            keyFile = mapper.readValue(path.toFile(), KeyFile.class);
        } catch (IOException e) {
            throw new KeyProviderException("Failed to load key file: " + path, e);
        }

        if (keyFile.keys != null) {
            for (KeyFileEntry entry : keyFile.keys) {
                KeyRecord record = toKeyRecord(entry, path.toString());
                store.computeIfAbsent(record.ref(), k -> new ArrayList<>()).add(record);
            }
        }

        // Sort each ref's versions descending
        store.values().forEach(
                list -> list.sort(Comparator.comparingInt(KeyRecord::version).reversed()));
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        List<KeyRecord> versions = store.get(ref);
        if (versions == null || versions.isEmpty()) {
            throw new KeyNotFoundException("No key found for ref: " + ref);
        }
        return versions.stream()
                .filter(r -> r.status() == Status.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new NoActiveKeyException(
                        "No active version found for ref: " + ref));
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        List<KeyRecord> versions = store.get(ref);
        if (versions == null || versions.isEmpty()) {
            throw new KeyNotFoundException("No key found for ref: " + ref);
        }
        KeyRecord record = versions.stream()
                .filter(r -> r.version() == version)
                .findFirst()
                .orElseThrow(() -> new KeyNotFoundException(
                        "No version " + version + " found for ref: " + ref));
        if (record.status() == Status.DISABLED) {
            throw new KeyDisabledException(
                    "Key ref='" + ref + "' version=" + version + " is disabled");
        }
        return record;
    }

    // --- private helpers ---

    private static KeyRecord toKeyRecord(KeyFileEntry entry, String filePath)
            throws KeyProviderException {
        if (entry.ref == null || entry.ref.isBlank()) {
            throw new KeyProviderException("Key entry missing 'ref' in file: " + filePath);
        }
        if (entry.algorithm == null || entry.algorithm.isBlank()) {
            throw new KeyProviderException(
                    "Key entry ref='" + entry.ref + "' missing 'algorithm' in file: " + filePath);
        }
        if (entry.material == null || entry.material.isBlank()) {
            throw new KeyProviderException(
                    "Key entry ref='" + entry.ref + "' missing 'material' in file: " + filePath);
        }

        Status status = parseStatus(entry.status, entry.ref, filePath);
        byte[] material = EnvProvider.decodeBytes(entry.material,
                "material for ref '" + entry.ref + "'");
        byte[] tweak = null;
        if (entry.tweak != null && !entry.tweak.isBlank()) {
            tweak = EnvProvider.decodeBytes(entry.tweak, "tweak for ref '" + entry.ref + "'");
        }

        Map<String, String> metadata = (entry.metadata != null)
                ? Map.copyOf(entry.metadata)
                : Map.of();

        Instant createdAt = null;
        if (entry.createdAt != null && !entry.createdAt.isBlank()) {
            try {
                createdAt = Instant.parse(entry.createdAt);
            } catch (Exception e) {
                throw new KeyProviderException(
                        "Invalid created_at '" + entry.createdAt + "' for ref '"
                                + entry.ref + "' in file: " + filePath, e);
            }
        }

        return new KeyRecord(entry.ref, entry.version, status, entry.algorithm,
                material, tweak, metadata, createdAt);
    }

    private static Status parseStatus(String raw, String ref, String filePath)
            throws KeyProviderException {
        if (raw == null || raw.isBlank()) {
            return Status.ACTIVE;
        }
        return switch (raw.toLowerCase()) {
            case "active" -> Status.ACTIVE;
            case "deprecated" -> Status.DEPRECATED;
            case "disabled" -> Status.DISABLED;
            default -> throw new KeyProviderException(
                    "Unknown status '" + raw + "' for ref '" + ref + "' in file: " + filePath);
        };
    }

    // --- Jackson-mapped DTOs ---

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class KeyFile {
        @JsonProperty("keys")
        List<KeyFileEntry> keys;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class KeyFileEntry {
        @JsonProperty("ref")
        String ref;

        @JsonProperty("version")
        int version = 1;

        @JsonProperty("status")
        String status;

        @JsonProperty("algorithm")
        String algorithm;

        @JsonProperty("material")
        String material;

        @JsonProperty("tweak")
        String tweak;

        @JsonProperty("metadata")
        Map<String, String> metadata;

        @JsonProperty("created_at")
        String createdAt;
    }
}
