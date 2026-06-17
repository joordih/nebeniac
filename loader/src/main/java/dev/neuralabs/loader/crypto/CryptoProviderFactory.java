package dev.neuralabs.loader.crypto;

import lombok.Getter;

import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class CryptoProviderFactory {

  private static volatile CryptoProviderFactory instance;
  @Getter
  private final ConcurrentHashMap<String, CryptoProvider> providers = new ConcurrentHashMap<>();
  @Getter
  private final Logger logger;

  private CryptoProviderFactory(Logger logger) {
    this.logger = logger;
    initializeProviders();
  }

  public static CryptoProviderFactory getInstance(Logger logger) {
    if (instance == null) {
      synchronized (CryptoProviderFactory.class) {
        if (instance == null) {
          instance = new CryptoProviderFactory(logger);
        }
      }
    }
    return instance;
  }

  private void initializeProviders() {
    providers.put("AES", new AESCryptoProvider());
    // Removed legacy NebeniacCompatibleCryptoProvider registration
    logger.info("Crypto providers initialized");
  }

  public CryptoProvider createNebeniacProvider(String encryptionKeyBase64) throws Exception {
    return new NebeniacCryptoProvider(encryptionKeyBase64, logger);
  }

  public CryptoProvider createProvider(String type) throws Exception {
    CryptoProvider provider = providers.get(type);
    if (provider == null) {
      throw new Exception("Unsupported crypto provider type: " + type);
    }
    return provider;
  }

}
