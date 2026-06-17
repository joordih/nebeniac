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


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class Session {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private String sessionToken;
  private String licenseKey;
  private String hardwareFingerprint;
  private Date createdAt;
  private Date lastHeartbeat;
  private Date expiresAt;
  private boolean active;
  private String clientIp;
  private String userAgent;

  public boolean isExpired() {
    return expiresAt != null && expiresAt.before(new Date());
  }

  public boolean isValid() {
    return active && !isExpired();
  }
}
