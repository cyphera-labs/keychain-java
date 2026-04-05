# Cyphera Keychain — Java

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

## License

MIT
