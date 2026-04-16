# Cyphera Keychain — Java

[![CI](https://github.com/cyphera-labs/keychain-java/actions/workflows/test.yml/badge.svg)](https://github.com/cyphera-labs/keychain-java/actions/workflows/test.yml)
[![Security](https://github.com/cyphera-labs/keychain-java/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/keychain-java/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
Key provider abstraction for the [Cyphera](https://cyphera.dev) Java SDK.

## Installation

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>dev.cyphera</groupId>
    <artifactId>keychain</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

### Memory provider (testing / development)

```java
import dev.cyphera.keychain.*;

var provider = new MemoryProvider(
    new KeyRecord("customer-primary", 1, Status.ACTIVE, "adf1",
        HexFormat.of().parseHex("0123456789abcdef0123456789abcdef"),
        "customer-ssn".getBytes(), Map.of(), null)
);

KeyRecord record = provider.resolve("customer-primary");
```

### Environment variable provider

```java
import dev.cyphera.keychain.*;

// Reads CYPHERA_CUSTOMER_PRIMARY_KEY (hex or base64)
var provider = new EnvProvider("CYPHERA");
KeyRecord record = provider.resolve("customer-primary");
```

### File provider

```java
import dev.cyphera.keychain.*;

var provider = new FileProvider("/etc/cyphera/keys.json");
KeyRecord record = provider.resolve("customer-primary");
```

Key file format:

```json
{
  "keys": [
    {
      "ref": "customer-primary",
      "version": 1,
      "status": "active",
      "algorithm": "adf1",
      "material": "<hex or base64>",
      "tweak": "<hex or base64>"
    }
  ]
}
```

## Providers

| Provider | Description | Use case |
|---|---|---|
| `MemoryProvider` | In-memory key store | Testing, development |
| `EnvProvider` | Keys from environment variables | 12-factor / container deployments |
| `FileProvider` | Keys from a local JSON file | Secrets manager file injection |

## Cloud KMS Providers

Cyphera Keychain supports four cloud KMS backends. Add the `keychain` artifact to your `pom.xml` (it bundles the provider implementations).

### AWS KMS

```java
import dev.cyphera.keychain.*;

// Uses default credential chain (env vars, instance profile, etc.)
var provider = new AwsKmsProvider("arn:aws:kms:us-east-1:123456789012:key/your-key-id");
KeyRecord record = provider.resolve("customer-primary");
```

For a custom region or endpoint (e.g., LocalStack):

```java
var provider = new AwsKmsProvider(
    "arn:aws:kms:us-east-1:000000000000:key/test-key",
    "us-east-1",
    "http://localhost:4566"
);
```

Each call to `resolve` generates an AES-256 data key via `GenerateDataKey` and caches
the plaintext in memory. `resolveVersion` only supports version `1`.

### GCP Cloud KMS

```java
import dev.cyphera.keychain.*;

String keyName = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key";
var provider = new GcpKmsProvider(keyName);
KeyRecord record = provider.resolve("customer-primary");
```

A random 32-byte data key is generated locally and wrapped (encrypted) via the GCP KMS
`encrypt` API. Application default credentials are used automatically.

### Azure Key Vault

```java
import dev.cyphera.keychain.*;

var provider = new AzureKvProvider("https://my-vault.vault.azure.net", "my-rsa-key");
KeyRecord record = provider.resolve("customer-primary");
```

Uses `DefaultAzureCredential` for authentication. A random 32-byte data key is generated
locally and wrapped with the specified RSA key via `wrapKey(RSA_OAEP)`.

Supply a custom `TokenCredential`:

```java
import com.azure.identity.ClientSecretCredentialBuilder;

var credential = new ClientSecretCredentialBuilder()
    .tenantId(tenantId)
    .clientId(clientId)
    .clientSecret(clientSecret)
    .build();
var provider = new AzureKvProvider("https://my-vault.vault.azure.net", "my-rsa-key", credential);
```

### HashiCorp Vault

```java
import dev.cyphera.keychain.*;

var provider = new VaultProvider("http://vault.example.com:8200", "s.mytoken");
KeyRecord record = provider.resolve("customer-primary");
```

Reads secrets from `secret/data/{ref}` (KV v2). The secret must contain these fields:

| Field       | Required | Description                          |
|-------------|----------|--------------------------------------|
| `material`  | yes      | Hex or base64 key bytes              |
| `algorithm` | no       | Algorithm ID, defaults to `adf1`     |
| `version`   | no       | Integer version, defaults to `1`     |
| `status`    | no       | `active`, `deprecated`, `disabled`   |
| `tweak`     | no       | Hex or base64 tweak bytes            |

Write a secret:

```
vault kv put secret/customer-primary \
  version=1 \
  status=active \
  algorithm=adf1 \
  material=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Use a custom mount:

```java
var provider = new VaultProvider("http://vault.example.com:8200", "s.mytoken", "kv");
```

### Updated provider table

| Provider        | Description                            | Use case                              |
|-----------------|----------------------------------------|---------------------------------------|
| `MemoryProvider`  | In-memory key store                  | Testing, development                  |
| `EnvProvider`     | Keys from environment variables      | 12-factor / container deployments     |
| `FileProvider`    | Keys from a local JSON file          | Secrets manager file injection        |
| `AwsKmsProvider`  | AWS KMS data-key generation          | AWS-hosted workloads                  |
| `GcpKmsProvider`  | GCP Cloud KMS envelope encryption   | GCP-hosted workloads                  |
| `AzureKvProvider` | Azure Key Vault key wrapping         | Azure-hosted workloads                |
| `VaultProvider`   | HashiCorp Vault KV v2                | Multi-cloud / on-premises deployments |

## License

MIT
