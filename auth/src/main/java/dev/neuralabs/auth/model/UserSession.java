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
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class UserSession {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String sessionId;
  private String userId;
  private String token;
  private String refreshToken;
  private Date createdAt;
  private Date expiresAt;
  private Date lastAccessAt;
  private String clientIp;
  private String userAgent;
  private boolean active;

  public boolean isValid() {
    return active && expiresAt != null && expiresAt.after(new Date());
  }

  public boolean isExpired() {
    return expiresAt != null && expiresAt.before(new Date());
  }
}
