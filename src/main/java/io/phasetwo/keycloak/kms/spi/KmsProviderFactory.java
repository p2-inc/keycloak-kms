package io.phasetwo.keycloak.kms.spi;

import org.keycloak.provider.ProviderFactory;

/** Factory for {@link KmsProvider}. Selected by {@code --spi-kms--provider=<id>}. */
public interface KmsProviderFactory extends ProviderFactory<KmsProvider> {}
