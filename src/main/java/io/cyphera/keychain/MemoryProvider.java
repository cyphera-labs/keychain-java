package io.cyphera.keychain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Thread-safe in-memory {@link KeyProvider} backed by a {@link ReadWriteLock}.
 *
 * <p>Suitable for testing and development scenarios where keys are known at construction time
 * or added incrementally via {@link #add(KeyRecord)}.</p>
 */
public final class MemoryProvider implements KeyProvider {

    /** Maps ref -> list of records sorted descending by version. */
    private final Map<String, List<KeyRecord>> store = new HashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    /**
     * Constructs a {@code MemoryProvider} pre-populated with the given records.
     *
     * @param records zero or more initial key records
     */
    public MemoryProvider(KeyRecord... records) {
        this(Arrays.asList(records));
    }

    /**
     * Constructs a {@code MemoryProvider} pre-populated with the given records.
     *
     * @param records initial key records
     */
    public MemoryProvider(List<KeyRecord> records) {
        for (KeyRecord r : records) {
            insertUnsafe(r);
        }
        sortAll();
    }

    /**
     * Adds a key record to the provider.
     *
     * <p>If a record with the same ref and version already exists it is replaced.</p>
     *
     * @param record the record to add
     */
    public void add(KeyRecord record) {
        lock.writeLock().lock();
        try {
            insertUnsafe(record);
            store.get(record.ref()).sort(Comparator.comparingInt(KeyRecord::version).reversed());
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        lock.readLock().lock();
        try {
            List<KeyRecord> versions = store.get(ref);
            if (versions == null || versions.isEmpty()) {
                throw new KeyNotFoundException("No key found for ref: " + ref);
            }
            return versions.stream()
                    .filter(r -> r.status() == Status.ACTIVE)
                    .findFirst()
                    .orElseThrow(() -> new NoActiveKeyException(
                            "No active version found for ref: " + ref));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        lock.readLock().lock();
        try {
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
        } finally {
            lock.readLock().unlock();
        }
    }

    // --- private helpers ---

    /** Must be called without holding the lock (used during construction). */
    private void insertUnsafe(KeyRecord record) {
        store.computeIfAbsent(record.ref(), k -> new ArrayList<>())
                .removeIf(r -> r.version() == record.version());
        store.get(record.ref()).add(record);
    }

    /** Sort all ref lists descending by version. Called once after bulk construction. */
    private void sortAll() {
        store.values().forEach(
                list -> list.sort(Comparator.comparingInt(KeyRecord::version).reversed()));
    }
}
