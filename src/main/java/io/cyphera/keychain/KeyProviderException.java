package io.cyphera.keychain;

/**
 * Base checked exception for all key-provider errors.
 */
public class KeyProviderException extends Exception {

    public KeyProviderException(String message) {
        super(message);
    }

    public KeyProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
