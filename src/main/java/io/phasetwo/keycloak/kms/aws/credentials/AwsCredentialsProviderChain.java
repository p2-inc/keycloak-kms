package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;

/**
 * The standard resolution order, most explicit first.
 *
 * <ol>
 *   <li>static configuration
 *   <li>{@code AWS_ACCESS_KEY_ID} and friends
 *   <li>container endpoint — EKS Pod Identity, then ECS task role
 *   <li>web identity — IRSA
 *   <li>EC2 instance profile
 * </ol>
 *
 * <p>Once a source succeeds the chain sticks to it, and refreshes through that same source when the
 * credentials approach expiry. Re-running the whole chain on every refresh would mean a transient
 * failure in the winning source silently demoting the server to a different identity — which would
 * show up as a confusing {@code AccessDeniedException} rather than as the outage it really is.
 */
@JBossLog
public class AwsCredentialsProviderChain implements AwsCredentialsProvider {

  private final List<AwsCredentialsProvider> sources;

  private volatile AwsCredentialsProvider winner;
  private volatile AwsCredentials cached;

  public AwsCredentialsProviderChain(List<AwsCredentialsProvider> sources) {
    this.sources = List.copyOf(sources);
  }

  /** The default chain. {@code staticProvider} may be null when nothing was configured. */
  public static AwsCredentialsProviderChain standard(
      Environment env, StaticCredentialsProvider staticProvider) {
    List<AwsCredentialsProvider> sources = new ArrayList<>();
    if (staticProvider != null) {
      sources.add(staticProvider);
    }
    sources.add(new EnvironmentCredentialsProvider(env));
    sources.add(new ContainerCredentialsProvider(env));
    sources.add(new WebIdentityCredentialsProvider(env));
    sources.add(new InstanceProfileCredentialsProvider());
    return new AwsCredentialsProviderChain(sources);
  }

  @Override
  public AwsCredentials resolveOrNull() {
    AwsCredentials current = cached;
    if (current != null && !current.isExpiring()) {
      return current;
    }
    synchronized (this) {
      if (cached != null && !cached.isExpiring()) {
        return cached;
      }
      if (winner != null) {
        AwsCredentials refreshed = winner.resolveOrNull();
        if (refreshed != null) {
          cached = refreshed;
          return refreshed;
        }
        log.warnf(
            "AWS credential source '%s' stopped providing credentials; re-running the whole chain",
            winner.name());
        winner = null;
      }
      return firstThatWorks();
    }
  }

  private AwsCredentials firstThatWorks() {
    List<String> tried = new ArrayList<>();
    for (AwsCredentialsProvider source : sources) {
      try {
        AwsCredentials c = source.resolveOrNull();
        if (c != null) {
          log.infof("AWS credentials resolved from %s (%s)", source.name(), c.accessKeyId());
          winner = source;
          cached = c;
          return c;
        }
        tried.add(source.name() + ": not configured");
      } catch (RuntimeException e) {
        // A source that was clearly intended but failed is worth surfacing rather than skipping
        // silently: "AWS_ROLE_ARN is set but the token file is unreadable" is the actual answer.
        log.warnf(e, "AWS credential source '%s' was applicable but failed", source.name());
        tried.add(source.name() + ": " + e.getMessage());
      }
    }
    log.errorf("No AWS credentials found. Tried: %s", String.join("; ", tried));
    return null;
  }

  @Override
  public AwsCredentials resolve() {
    AwsCredentials c = resolveOrNull();
    if (c == null) {
      throw new KmsException(
          "No AWS credentials available. Configure a role (IRSA, EKS Pod Identity, ECS task role or"
              + " EC2 instance profile), set AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or set"
              + " --spi-kms--aws--access-key-id and --spi-kms--aws--secret-access-key. Sources"
              + " tried, in order: "
              + String.join(", ", sources.stream().map(AwsCredentialsProvider::name).toList()));
    }
    return c;
  }

  @Override
  public String name() {
    AwsCredentialsProvider w = winner;
    return w == null ? "chain" : w.name();
  }

  /** For the startup log line. Null until something has been resolved. */
  public String resolvedSource() {
    AwsCredentialsProvider w = winner;
    return w == null ? null : w.name();
  }
}
