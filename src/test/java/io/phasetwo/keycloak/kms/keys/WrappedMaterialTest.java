package io.phasetwo.keycloak.kms.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WrappedMaterialTest {

  @Test
  @DisplayName("round-trips arbitrary ciphertext")
  void roundTrip() {
    byte[] ciphertext = new byte[512];
    for (int i = 0; i < ciphertext.length; i++) {
      ciphertext[i] = (byte) i;
    }
    String encoded = WrappedMaterial.encode(ciphertext);
    assertTrue(encoded.startsWith("kms://v1/"));
    assertArrayEquals(ciphertext, WrappedMaterial.decode(encoded));
  }

  @Test
  @DisplayName("encodes url-safe and unpadded, so the value survives config and query strings")
  void urlSafeUnpadded() {
    // 0xFB 0xFF produce '+' and '/' under standard base64; url-safe gives '-' and '_'.
    String encoded = WrappedMaterial.encode(new byte[] {(byte) 0xfb, (byte) 0xff, (byte) 0xbf});
    assertFalse(encoded.substring("kms://v1/".length()).contains("+"));
    assertFalse(encoded.substring("kms://v1/".length()).contains("="));
    assertFalse(encoded.substring("kms://v1/".length()).contains("/"));
  }

  @Test
  @DisplayName("a future version is a legible error, not a decrypt failure")
  void unknownVersionIsLegible() {
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> WrappedMaterial.decode("kms://v2/AAAA"));
    assertTrue(e.getMessage().contains("v2"), e.getMessage());
    assertTrue(e.getMessage().contains("v1"), e.getMessage());
  }

  @ParameterizedTest
  @DisplayName("refuses anything that is not a kms:// value")
  @ValueSource(
      strings = {
        "",
        "   ",
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ",
        "vault://secret/key",
        "kms:/v1/AAAA"
      })
  void refusesNonKmsValues(String value) {
    assertThrows(IllegalArgumentException.class, () -> WrappedMaterial.decode(value));
  }

  @Test
  @DisplayName("refuses null rather than NPE-ing somewhere less obvious")
  void refusesNull() {
    assertThrows(IllegalArgumentException.class, () -> WrappedMaterial.decode(null));
  }

  @Test
  @DisplayName("isWrapped distinguishes migrated config from legacy plaintext config")
  void isWrapped() {
    assertTrue(
        WrappedMaterial.isWrapped(WrappedMaterial.encode("x".getBytes(StandardCharsets.UTF_8))));
    assertFalse(WrappedMaterial.isWrapped("MIIEvQIBADANBgkq"));
    assertFalse(WrappedMaterial.isWrapped(null));
  }

  @Test
  @DisplayName("the on-disk format is pinned, because changing it is a migration")
  void formatIsStable() {
    // Pinned deliberately: this string shape is what lands in COMPONENT_CONFIG. Changing it is a
    // migration, not a refactor.
    assertEquals("kms://v1/AQID", WrappedMaterial.encode(new byte[] {1, 2, 3}));
  }
}
