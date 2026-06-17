package dev.neuralabs.loader.crypto;

public interface CryptoProvider {

  String getAlgorithmName();

  byte[] generateKey(String seed, String context);

  byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws CryptoException;

  byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws CryptoException;

  byte[] generateIV();

  int getKeySize();

  int getIVSize();
}
