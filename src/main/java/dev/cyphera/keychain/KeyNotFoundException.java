package dev.cyphera.keychain;

/**
 * Thrown when no key matching the requested ref (and optional version) exists.
 */
public class KeyNotFoundException extends KeyProviderException {

    public KeyNotFoundException(String message) {
        super(message);
    }

    public KeyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
