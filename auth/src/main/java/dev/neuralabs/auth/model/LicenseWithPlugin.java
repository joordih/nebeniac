package dev.neuralabs.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LicenseWithPlugin {

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
