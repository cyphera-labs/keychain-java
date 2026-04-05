package dev.cyphera.keychain;

/**
 * Lifecycle status of a key record.
 */
public enum Status {
    /** The key is available for encryption and decryption. */
    ACTIVE,
    /** The key should not be used for new encryptions but may still decrypt. */
    DEPRECATED,
    /** The key is completely disabled and must not be used. */
    DISABLED
}
