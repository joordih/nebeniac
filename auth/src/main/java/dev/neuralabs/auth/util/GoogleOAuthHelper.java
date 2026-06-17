package dev.neuralabs.auth.util;

import java.awt.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;


public class GoogleOAuthHelper {

  private static final String CLIENT_ID = "541579947775-7hkenbfuukrc7g7sctg7hokm37k6gi7b.apps.googleusercontent.com";
  private static final String CLIENT_SECRET = "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";
  private static final String REDIRECT_URI = "http://localhost:8080/oauth/callback";
  private static final String SCOPE = "https://www.googleapis.com/auth/gmail.send";

  public static void main(String[] args) {
    try {
      String authUrl = generateAuthUrl();

      if (Desktop.isDesktopSupported()) {
        Desktop.getDesktop().browse(URI.create(authUrl));
      }

      Scanner scanner = new Scanner(System.in);
      System.out.print("\nEnter the authorization code: ");
      String authCode = scanner.nextLine().trim();

      String refreshToken = exchangeCodeForTokens(authCode);

      if (refreshToken == null) {
        System.err.println("Error obtaining refresh token");
      }

      scanner.close();

    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
    }
  }

  private static String generateAuthUrl() {
    return "https://accounts.google.com/o/oauth2/auth?" +
        "client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8) +
        "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8) +
        "&scope=" + URLEncoder.encode(SCOPE, StandardCharsets.UTF_8) +
        "&response_type=code" +
        "&access_type=offline" +
        "&prompt=consent";
  }

  private static String exchangeCodeForTokens(String authCode) {
    try {
      String requestBody = "grant_type=authorization_code" +
          "&client_id=" + URLEncoder.encode(CLIENT_ID, StandardCharsets.UTF_8) +
          "&client_secret=" + URLEncoder.encode(CLIENT_SECRET, StandardCharsets.UTF_8) +
          "&redirect_uri=" + URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8) +
          "&code=" + URLEncoder.encode(authCode, StandardCharsets.UTF_8);

      HttpClient client = HttpClient.newHttpClient();
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create("https://oauth2.googleapis.com/token"))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {
        String responseBody = response.body();
        String refreshToken = extractJsonValue(responseBody, "refresh_token");
        return refreshToken;
      } else {
        System.err.println("Error HTTP: " + response.statusCode());
        System.err.println("Respuesta: " + response.body());
        return null;
      }

    } catch (Exception e) {
      System.err.println("Error exchanging code: " + e.getMessage());
      return null;
    }
  }

  private static String extractJsonValue(String json, String key) {
    String searchKey = "\"" + key + "\"";
    int keyIndex = json.indexOf(searchKey);
    if (keyIndex == -1)
      return null;

    int colonIndex = json.indexOf(":", keyIndex);
    if (colonIndex == -1)
      return null;

    int valueStart = colonIndex + 1;
    while (valueStart < json.length() && (json.charAt(valueStart) == ' ' || json.charAt(valueStart) == '"')) {
      valueStart++;
    }

    int valueEnd = valueStart;
    while (valueEnd < json.length() && json.charAt(valueEnd) != '"' && json.charAt(valueEnd) != ','
        && json.charAt(valueEnd) != '}') {
      valueEnd++;
    }

    return json.substring(valueStart, valueEnd);
  }
}
