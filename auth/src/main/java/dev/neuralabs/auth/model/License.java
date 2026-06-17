package dev.neuralabs.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.mongojack.Id;
import org.mongojack.ObjectId;

import java.util.Date;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class License {

  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private String licenseKey;
  private String customerEmail;
  private String customerName;
  private String licenseType;
  private boolean active;
  private int maxActivations;
  private List<String> features;
  private Date createdAt;
  private Date updatedAt;
  private Date expiresAt;
  private String notes;
  private String pluginId;

  private String encryptionKey;
  private String perLicenseSalt;
  private List<String> targetPackages;
  private Map<String, Object> encryptionMetadata;

  public boolean isExpired() {
    return expiresAt != null && expiresAt.before(new Date());
  }

  public boolean canBeUsed() {
    return active && !isExpired();
  }

  public boolean hasFeature(String feature) {
    return features != null && features.contains(feature);
  }
}
