package io.phasetwo.keycloak.kms.aws;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.aws.credentials.AwsCredentialsProviderChain;
import io.phasetwo.keycloak.kms.aws.credentials.Environment;
import io.phasetwo.keycloak.kms.aws.credentials.StaticCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsProviderFactory;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Wires AWS KMS in, and refuses to let the server start if it cannot be reached.
 *
 * <p>The fail-fast is the point. A key-custody extension that starts anyway when its KMS is
 * unreachable is worse than not installing one: realms keep serving from whatever keys they have,
 * the operator sees a healthy server, and the control everybody believes is in place is not. So a
 * missing key, a disabled key, a key of the wrong type, or an IAM policy that does not permit
 * {@code DescribeKey} all stop startup with a message naming which it was.
 */
@JBossLog
@AutoService(KmsProviderFactory.class)
public class AwsKmsProviderFactory implements KmsProviderFactory {

  public static final String ID = "aws";

  private Environment env = Environment.SYSTEM;
  private volatile AwsKmsProvider provider;
  private volatile AwsCredentialsProviderChain credentials;
  private String region;
  private String keyId;

  /** Test seam: swap the environment before {@link #init}. */
  public void setEnvironment(Environment env) {
    this.env = env;
  }

  @Override
  public KmsProvider create(KeycloakSession session) {
    return provider;
  }

  @Override
  public void init(Config.Scope config) {
    this.region = resolveRegion(config);
    this.keyId = config.get("keyId");

    StaticCredentialsProvider staticCredentials =
        new StaticCredentialsProvider(
            config.get("accessKeyId"), config.get("secretAccessKey"), config.get("sessionToken"));
    this.credentials = AwsCredentialsProviderChain.standard(env, staticCredentials);

    KmsApi api = new KmsApi(credentials, region, config.get("endpoint"));
    this.provider = new AwsKmsProvider(api, keyId);
  }

  private String resolveRegion(Config.Scope config) {
    String r = config.get("region", env.get("AWS_REGION", env.get("AWS_DEFAULT_REGION", null)));
    if (r == null || r.isBlank()) {
      throw new KmsException(
          "keycloak-kms: no AWS region. Set --spi-kms--aws--region (or AWS_REGION). There is no"
              + " safe default — signing the wrong region's endpoint fails with an error that does"
              + " not mention regions.");
    }
    return r;
  }

  /**
   * Prove the configuration works before the server accepts traffic.
   *
   * <p>Deliberately not lazy. Discovering an IAM problem at the first login means discovering it in
   * production, on a user's request, as a 500.
   */
  @Override
  public void postInit(KeycloakSessionFactory factory) {
    if (keyId == null || keyId.isBlank()) {
      log.warn(
          "keycloak-kms: no default AWS KMS key configured (--spi-kms--aws--key-id). Envelope-mode"
              + " key providers will fail unless each one sets its own kmsKeyId. Native-mode"
              + " providers always name their own key, so this is fine if you use only those.");
      return;
    }

    KmsKeyDescription key;
    try {
      key = provider.describe(keyId);
    } catch (RuntimeException e) {
      throw new KmsException(
          "keycloak-kms: cannot reach AWS KMS key '"
              + keyId
              + "' in "
              + region
              + " — refusing to start, because starting anyway would leave realms serving keys this"
              + " extension is supposed to be protecting. "
              + e.getMessage(),
          e);
    }

    if (!key.enabled()) {
      throw new KmsException(
          "keycloak-kms: KMS key "
              + key
              + " is disabled or pending deletion. Realms whose material"
              + " is wrapped under it cannot be read until it is re-enabled.");
    }
    if (!key.isSymmetric()) {
      throw new KmsException(
          "keycloak-kms: the default key "
              + key
              + " has usage "
              + key.keyUsage()
              + ", but envelope mode needs an ENCRYPT_DECRYPT (SYMMETRIC_DEFAULT) key. An"
              + " asymmetric SIGN_VERIFY key belongs on an individual native-mode provider's"
              + " kmsKeyId, not here.");
    }

    log.infof(
        "keycloak-kms: AWS KMS ready — key=%s region=%s credentials=%s",
        key, region, credentials.resolvedSource());
  }

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name("region")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("AWS region of the KMS endpoint. Falls back to AWS_REGION / AWS_DEFAULT_REGION.")
        .add()
        .property()
        .name("keyId")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Default symmetric CMK for envelope mode: an ARN, a key id, or alias/name. A key"
                + " provider component may override it with its own kmsKeyId.")
        .add()
        .property()
        .name("endpoint")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Override the KMS endpoint URL. For LocalStack and tests.")
        .add()
        .property()
        .name("accessKeyId")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Static access key id. Discouraged: prefer IRSA, EKS Pod Identity, an ECS task role or"
                + " an EC2 instance profile, all of which are detected automatically.")
        .add()
        .property()
        .name("secretAccessKey")
        .type(ProviderConfigProperty.PASSWORD)
        .secret(true)
        .helpText("Static secret access key. See accessKeyId.")
        .add()
        .property()
        .name("sessionToken")
        .type(ProviderConfigProperty.PASSWORD)
        .secret(true)
        .helpText("Session token, if the static credentials are temporary.")
        .add()
        .build();
  }
}
