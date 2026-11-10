package dev.neuralabs.auth.util;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.neuralabs.auth.model.License;
import dev.neuralabs.auth.model.Plugin;
import java.util.Set;

public final class GsonUtil {
  private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  private static final Set<Class<?>> KEY_HOLDERS = Set.of(License.class, Plugin.class);

  private static final ExclusionStrategy HIDE_KEY_MATERIAL = new ExclusionStrategy() {
    @Override
    public boolean shouldSkipField(FieldAttributes field) {
      return KEY_HOLDERS.contains(field.getDeclaringClass()) && "encryptionKey".equals(field.getName());
    }

    @Override
    public boolean shouldSkipClass(Class<?> clazz) {
      return false;
    }
  };

  private GsonUtil() {}

  public static Gson buildApi() {
    return new GsonBuilder().setDateFormat(DATE_FORMAT).addSerializationExclusionStrategy(HIDE_KEY_MATERIAL).create();
  }

  public static Gson build() {
    return new GsonBuilder().setDateFormat(DATE_FORMAT).create();
  }

  public static Gson buildPretty() {
    return new GsonBuilder().setPrettyPrinting().setDateFormat(DATE_FORMAT).create();
  }
}
