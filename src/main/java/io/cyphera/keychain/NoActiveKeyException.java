package io.cyphera.keychain;

/**
 * Thrown when a key ref exists but none of its versions has {@link Status#ACTIVE} status.
 */
public class NoActiveKeyException extends KeyProviderException {

    public NoActiveKeyException(String message) {
        super(message);
    }

    public NoActiveKeyException(String message, Throwable cause) {
        super(message, cause);
    }
}
