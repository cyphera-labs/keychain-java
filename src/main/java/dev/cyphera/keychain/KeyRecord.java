package dev.cyphera.keychain;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable representation of a cryptographic key.
 *
 * <p>Because Java records do not provide deep equality for array fields, this is implemented
 * as a plain immutable class with final fields rather than a {@code record}.</p>
 */
public final class KeyRecord {

    private final String ref;
    private final int version;
    private final Status status;
    private final String algorithm;
    private final byte[] material;
    private final byte[] tweak;
    private final Map<String, String> metadata;
    private final Instant createdAt;

    /**
     * Constructs a new {@code KeyRecord}.
     *
     * @param ref       logical identifier for this key
     * @param version   monotonically increasing version number
     * @param status    lifecycle status of the key
     * @param algorithm algorithm identifier (e.g. {@code "adf1"})
     * @param material  raw key bytes; copied defensively
     * @param tweak     optional tweak bytes; copied defensively; may be {@code null}
     * @param metadata  arbitrary string metadata; may be {@code null}
     * @param createdAt creation timestamp; may be {@code null}
     */
    public KeyRecord(
            String ref,
            int version,
            Status status,
            String algorithm,
            byte[] material,
            byte[] tweak,
            Map<String, String> metadata,
            Instant createdAt) {
        this.ref = Objects.requireNonNull(ref, "ref must not be null");
        this.version = version;
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.material = Arrays.copyOf(
                Objects.requireNonNull(material, "material must not be null"),
                material.length);
        this.tweak = (tweak != null) ? Arrays.copyOf(tweak, tweak.length) : null;
        this.metadata = (metadata != null)
                ? Collections.unmodifiableMap(Map.copyOf(metadata))
                : Collections.emptyMap();
        this.createdAt = createdAt;
    }

    /** Returns the logical key reference. */
    public String ref() {
        return ref;
    }

    /** Returns the version number. */
    public int version() {
        return version;
    }

    /** Returns the lifecycle status. */
    public Status status() {
        return status;
    }

    /** Returns the algorithm identifier. */
    public String algorithm() {
        return algorithm;
    }

    /**
     * Returns a defensive copy of the raw key material.
     */
    public byte[] material() {
        return Arrays.copyOf(material, material.length);
    }

    /**
     * Returns a defensive copy of the tweak bytes, or {@code null} if none was set.
     */
    public byte[] tweak() {
        return (tweak != null) ? Arrays.copyOf(tweak, tweak.length) : null;
    }

    /** Returns an unmodifiable view of the metadata map. */
    public Map<String, String> metadata() {
        return metadata;
    }

    /** Returns the creation timestamp, or {@code null} if not set. */
    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyRecord other)) return false;
        return version == other.version
                && ref.equals(other.ref)
                && status == other.status
                && algorithm.equals(other.algorithm)
                && Arrays.equals(material, other.material)
                && Arrays.equals(tweak, other.tweak)
                && metadata.equals(other.metadata)
                && Objects.equals(createdAt, other.createdAt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(ref, version, status, algorithm, metadata, createdAt);
        result = 31 * result + Arrays.hashCode(material);
        result = 31 * result + Arrays.hashCode(tweak);
        return result;
    }

    @Override
    public String toString() {
        return "KeyRecord{ref='" + ref + "', version=" + version
                + ", status=" + status + ", algorithm='" + algorithm + "'}";
    }
}
