package io.cyphera.keychain;

/**
 * Thrown when a key record is found but its status is {@link Status#DISABLED}.
 */
public class KeyDisabledException extends KeyProviderException {

    public KeyDisabledException(String message) {
        super(message);
    }

    public KeyDisabledException(String message, Throwable cause) {
        super(message, cause);
    }
}
