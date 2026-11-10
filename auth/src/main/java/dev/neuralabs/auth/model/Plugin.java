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
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class Plugin {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private String pluginId;
  private String name;
  private String version;
  private String description;
  private String originalMainClass;
  private String encryptionKey;
  private String ownerId;
  private boolean active;
  private Date createdAt;
  private Date updatedAt;
  private String jarHash;
  private List<String> targetPackages;

  public boolean canBeUsed() {
    return active;
  }
}
