package dev.cyphera.keychain;

/**
 * Abstraction for resolving cryptographic key records.
 *
 * <p>Implementations must be thread-safe.</p>
 */
public interface KeyProvider {

    /**
     * Resolves the highest-version {@link Status#ACTIVE} record for the given ref.
     *
     * @param ref logical key identifier
     * @return the active {@link KeyRecord} with the highest version number
     * @throws KeyNotFoundException   if no records exist for {@code ref}
     * @throws NoActiveKeyException   if records exist but none is {@link Status#ACTIVE}
     * @throws KeyProviderException   for any other provider-level error
     */
    KeyRecord resolve(String ref) throws KeyProviderException;

    /**
     * Resolves the record for a specific ref and version.
     *
     * @param ref     logical key identifier
     * @param version exact version to retrieve
     * @return the {@link KeyRecord} matching ref and version
     * @throws KeyNotFoundException   if no such ref/version combination exists
     * @throws KeyDisabledException   if the record exists but is {@link Status#DISABLED}
     * @throws KeyProviderException   for any other provider-level error
     */
    KeyRecord resolveVersion(String ref, int version) throws KeyProviderException;
}
