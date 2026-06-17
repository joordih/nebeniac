package dev.neuralabs.auth.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public final class GsonUtil {

  private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  private GsonUtil() {}

  public static Gson build() {
    return new GsonBuilder().setDateFormat(DATE_FORMAT).create();
  }

  public static Gson buildPretty() {
    return new GsonBuilder().setPrettyPrinting().setDateFormat(DATE_FORMAT).create();
  }
}
