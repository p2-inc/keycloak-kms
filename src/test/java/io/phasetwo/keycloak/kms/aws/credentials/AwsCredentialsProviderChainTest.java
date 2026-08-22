package io.phasetwo.keycloak.kms.aws.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.TestEnvironment;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AwsCredentialsProviderChainTest {

  /** A source whose behaviour the test controls, counting how often it is asked. */
  static final class Source implements AwsCredentialsProvider {
    final String name;
    final AtomicInteger calls = new AtomicInteger();
    volatile AwsCredentials next;
    volatile RuntimeException failure;

    Source(String name, AwsCredentials next) {
      this.name = name;
      this.next = next;
    }

    @Override
    public AwsCredentials resolveOrNull() {
      calls.incrementAndGet();
      if (failure != null) {
        throw failure;
      }
      return next;
    }

    @Override
    public String name() {
      return name;
    }
  }

  private static AwsCredentials creds(String id) {
    return AwsCredentials.longLived(id, "secret", "test");
  }

  private static AwsCredentials expiring(String id) {
    return new AwsCredentials(id, "secret", "tok", Instant.now().plusSeconds(30), "test");
  }

  @Test
  @DisplayName("the first applicable source wins and later ones are never consulted")
  void precedence() {
    Source first = new Source("first", null);
    Source second = new Source("second", creds("SECOND"));
    Source third = new Source("third", creds("THIRD"));

    AwsCredentialsProviderChain chain =
        new AwsCredentialsProviderChain(List.of(first, second, third));

    assertEquals("SECOND", chain.resolve().accessKeyId());
    assertEquals(1, first.calls.get());
    assertEquals(1, second.calls.get());
    assertEquals(0, third.calls.get(), "a source after the winner must not be probed");
  }

  @Test
  @DisplayName("the standard chain prefers explicit configuration over the environment")
  void standardChainPrefersStatic() {
    AwsCredentialsProviderChain chain =
        AwsCredentialsProviderChain.standard(
            new TestEnvironment()
                .var("AWS_ACCESS_KEY_ID", "FROM_ENV")
                .var("AWS_SECRET_ACCESS_KEY", "s"),
            new StaticCredentialsProvider("FROM_CONFIG", "s", null));
    assertEquals("FROM_CONFIG", chain.resolve().accessKeyId());
  }

  @Test
  @DisplayName("the standard chain falls back to the environment when nothing is configured")
  void standardChainFallsBackToEnv() {
    AwsCredentialsProviderChain chain =
        AwsCredentialsProviderChain.standard(
            new TestEnvironment()
                .var("AWS_ACCESS_KEY_ID", "FROM_ENV")
                .var("AWS_SECRET_ACCESS_KEY", "s"),
            null);
    assertEquals("FROM_ENV", chain.resolve().accessKeyId());
    assertEquals("environment", chain.resolvedSource());
  }

  @Test
  @DisplayName("non-expiring credentials are cached, not re-resolved on every call")
  void cachesNonExpiring() {
    Source only = new Source("only", creds("A"));
    AwsCredentialsProviderChain chain = new AwsCredentialsProviderChain(List.of(only));
    chain.resolve();
    chain.resolve();
    chain.resolve();
    assertEquals(1, only.calls.get());
  }

  @Test
  @DisplayName("expiring credentials refresh through the winning source, not the whole chain")
  void refreshesThroughWinner() {
    Source first = new Source("first", null);
    Source second = new Source("second", expiring("EXPIRING"));
    AwsCredentialsProviderChain chain = new AwsCredentialsProviderChain(List.of(first, second));

    chain.resolve();
    assertEquals(1, first.calls.get());

    second.next = creds("FRESH");
    assertEquals("FRESH", chain.resolve().accessKeyId());
    assertEquals(2, second.calls.get());
    assertEquals(1, first.calls.get(), "refresh must not re-probe earlier sources");
  }

  @Test
  @DisplayName("a winner that stops working sends the chain round again rather than failing shut")
  void reRunsChainWhenWinnerStops() {
    Source first = new Source("first", null);
    Source second = new Source("second", expiring("FROM_SECOND"));
    AwsCredentialsProviderChain chain = new AwsCredentialsProviderChain(List.of(first, second));

    assertEquals("FROM_SECOND", chain.resolve().accessKeyId());

    // The winner goes away; another source has meanwhile become available.
    second.next = null;
    first.next = creds("FROM_FIRST");
    assertEquals("FROM_FIRST", chain.resolve().accessKeyId());
    assertEquals("first", chain.resolvedSource());
  }

  @Test
  @DisplayName("a source that throws is logged and skipped, not fatal to the chain")
  void throwingSourceIsSkipped() {
    Source broken = new Source("broken", null);
    broken.failure = new KmsException("token file unreadable");
    Source working = new Source("working", creds("OK"));

    AwsCredentialsProviderChain chain = new AwsCredentialsProviderChain(List.of(broken, working));
    assertEquals("OK", chain.resolve().accessKeyId());
  }

  @Test
  @DisplayName("no source at all produces an error that names every source that was tried")
  void nothingWorks() {
    AwsCredentialsProviderChain chain =
        new AwsCredentialsProviderChain(
            List.of(new Source("alpha", null), new Source("beta", null)));
    assertNull(chain.resolveOrNull());
    KmsException e = assertThrows(KmsException.class, chain::resolve);
    assertTrue(e.getMessage().contains("alpha"), e.getMessage());
    assertTrue(e.getMessage().contains("beta"), e.getMessage());
    assertTrue(e.getMessage().contains("IRSA"), "the error should say what to configure");
  }

  @Test
  @DisplayName("resolvedSource is null until something resolves, then names the winner")
  void resolvedSourceReporting() {
    Source only = new Source("only", creds("A"));
    AwsCredentialsProviderChain chain = new AwsCredentialsProviderChain(List.of(only));
    assertNull(chain.resolvedSource());
    chain.resolve();
    assertEquals("only", chain.resolvedSource());
  }
}
