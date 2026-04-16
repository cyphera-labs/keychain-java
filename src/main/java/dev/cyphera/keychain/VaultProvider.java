package dev.cyphera.keychain;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Key provider backed by HashiCorp Vault KV v2 secrets engine.
 *
 * <p>Key records are stored at {@code {mount}/data/{ref}} with fields:
 * version, status, algorithm, material (hex or base64), tweak (optional).
 *
 * <p>Example secret data (written with {@code vault kv put secret/my-key
 * version=1 status=active algorithm=adf1 material=aabb...}):
 */
public final class VaultProvider implements KeyProvider {

    private final Vault vault;
    private final String mount;

    public VaultProvider(String address, String token) throws VaultException {
        this(address, token, "secret");
    }

    public VaultProvider(String address, String token, String mount) throws VaultException {
        VaultConfig config = new VaultConfig()
                .address(address)
                .token(token)
                .engineVersion(1)
                .build();
        this.vault = Vault.create(config);
        this.mount = mount;
    }

    /** Package-private constructor for testing. */
    VaultProvider(Vault vault, String mount) {
        this.vault = vault;
        this.mount = mount;
    }

    private static byte[] decodeBytes(String value) {
        String s = value.strip();
        if (s.length() % 2 == 0 && s.matches("[0-9a-fA-F]+")) {
            try {
                return HexFormat.of().parseHex(s);
            } catch (IllegalArgumentException ignored) {
            }
        }
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return Base64.getUrlDecoder().decode(s);
        }
    }

    private Map<String, String> readData(String ref) throws KeyNotFoundException {
        try {
            LogicalResponse response = vault.logical().read(mount + "/data/" + ref);
            if (response.getRestResponse().getStatus() == 404) {
                throw new KeyNotFoundException("Key not found: " + ref);
            }
            Map<String, String> outerData = response.getData();
            if (outerData == null || outerData.isEmpty()) {
                throw new KeyNotFoundException("Key not found: " + ref);
            }
            // KV v2 nests secret data under "data" key; the outer map also has "metadata"
            // The jopenlibs driver flattens the JSON into string values, so "data" contains
            // the JSON string of the inner map. Try to parse it if present.
            if (outerData.containsKey("data") && !outerData.containsKey("material")) {
                try {
                    @SuppressWarnings("unchecked")
                    Map<String, String> innerData = new com.fasterxml.jackson.databind.ObjectMapper()
                            .readValue(outerData.get("data"),
                                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, String>>() {});
                    return innerData;
                } catch (Exception ignored) {
                    // Fall through to outer data if parsing fails
                }
            }
            return outerData;
        } catch (VaultException e) {
            throw new KeyNotFoundException("Key not found: " + ref, e);
        }
    }

    private KeyRecord parseOne(String ref, Map<String, String> data) {
        int version = 1;
        String vStr = data.get("version");
        if (vStr != null) {
            try { version = Integer.parseInt(vStr); } catch (NumberFormatException ignored) {}
        }
        String statusStr = data.getOrDefault("status", "active").toLowerCase();
        Status status = switch (statusStr) {
            case "deprecated" -> Status.DEPRECATED;
            case "disabled" -> Status.DISABLED;
            default -> Status.ACTIVE;
        };
        String algorithm = data.getOrDefault("algorithm", "adf1");
        String materialStr = data.getOrDefault("material", "");
        byte[] material = materialStr.isEmpty() ? new byte[0] : decodeBytes(materialStr);
        String tweakStr = data.get("tweak");
        byte[] tweak = tweakStr != null && !tweakStr.isEmpty() ? decodeBytes(tweakStr) : null;
        return new KeyRecord(ref, version, status, algorithm, material, tweak, Map.of(), null);
    }

    private List<KeyRecord> parseRecords(String ref, Map<String, String> data) {
        return List.of(parseOne(ref, data));
    }

    @Override
    public KeyRecord resolve(String ref) throws KeyProviderException {
        Map<String, String> data = readData(ref);
        List<KeyRecord> records = parseRecords(ref, data);
        return records.stream()
                .filter(r -> r.status() == Status.ACTIVE)
                .max(java.util.Comparator.comparingInt(KeyRecord::version))
                .orElseThrow(() -> new NoActiveKeyException("No active key: " + ref));
    }

    @Override
    public KeyRecord resolveVersion(String ref, int version) throws KeyProviderException {
        Map<String, String> data = readData(ref);
        List<KeyRecord> records = parseRecords(ref, data);
        for (KeyRecord r : records) {
            if (r.version() == version) {
                if (r.status() == Status.DISABLED) {
                    throw new KeyDisabledException("Key disabled: " + ref + " version " + version);
                }
                return r;
            }
        }
        throw new KeyNotFoundException("Key not found: " + ref + " version " + version);
    }
}
