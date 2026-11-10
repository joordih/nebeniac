package dev.neuralabs.loader.crypto.e2ee;

import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

public final class E2EEResponseDecryptor {
  private E2EEResponseDecryptor() {}

  public static String decrypt(String responseBody, TinkE2EEClient.EncryptedRequest request)
      throws DecryptionException {
    JsonObject envelope;
    try {
      envelope = JsonParser.parseString(responseBody).getAsJsonObject();
    } catch (RuntimeException e) {
      throw new DecryptionException("Malformed response from backend", e);
    }

    if (!envelope.has("encrypted") || !envelope.get("encrypted").getAsBoolean() || !envelope.has("ciphertext")) {
      throw new DecryptionException("Backend response is not encrypted");
    }

    try {
      byte[] ciphertext = Base64.getDecoder().decode(envelope.get("ciphertext").getAsString());
      byte[] associatedData = request.getNonce().getBytes(StandardCharsets.UTF_8);
      byte[] plaintext = new AesGcmJce(request.getResponseKey()).decrypt(ciphertext, associatedData);
      return new String(plaintext, StandardCharsets.UTF_8);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new DecryptionException("Backend response failed authentication", e);
    }
  }

  public static class DecryptionException extends Exception {
    public DecryptionException(String message) {
      super(message);
    }

    public DecryptionException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
