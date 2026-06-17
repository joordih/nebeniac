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

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class User {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private String email;
  private String username;
  private String passwordHash;
  private String firstName;
  private String lastName;
  private String role;
  private boolean active;
  private boolean emailVerified;
  private String emailVerificationToken;
  private String passwordResetToken;
  private Date passwordResetExpires;
  private Date createdAt;
  private Date updatedAt;
  private Date lastLoginAt;
  private String createdBy;
  private List<String> permissions;

  public boolean isAdmin() {
    return "ADMIN".equals(role);
  }

  public boolean isUser() {
    return "USER".equals(role);
  }

  public boolean canLogin() {
    return active && emailVerified;
  }

  public String getFullName() {
    if (firstName != null && lastName != null) {
      return firstName + " " + lastName;
    }
    return username != null ? username : email;
  }
}
