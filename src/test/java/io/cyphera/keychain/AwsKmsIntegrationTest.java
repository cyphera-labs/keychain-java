package io.cyphera.keychain;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyRequest;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

@Tag("integration")
@EnabledIfEnvironmentVariable(named = "AWS_ENDPOINT_URL", matches = ".+")
class AwsKmsIntegrationTest {

    @Test
    void resolve_returnsActiveKey_againstLocalStack() throws Exception {
        String endpoint = System.getenv("AWS_ENDPOINT_URL");
        String region = System.getenv().containsKey("AWS_DEFAULT_REGION")
                ? System.getenv("AWS_DEFAULT_REGION") : "us-east-1";

        KmsClient admin = KmsClient.builder()
                .region(Region.of(region))
                .endpointOverride(URI.create(endpoint))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create("test", "test")))
                .build();

        String keyId = admin.createKey(CreateKeyRequest.builder()
                .description("Cyphera integration test")
                .build()).keyMetadata().keyId();

        AwsKmsProvider provider = new AwsKmsProvider(keyId, region, endpoint);
        KeyRecord rec = provider.resolve("integ-primary");
        assertEquals(Status.ACTIVE, rec.status());
        assertEquals(32, rec.material().length);
    }
}
