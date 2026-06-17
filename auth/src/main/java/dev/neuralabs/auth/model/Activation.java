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
public class Activation {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private String licenseKey;
  private String hardwareFingerprint;
  private String serverName;
  private String serverIp;
  private int serverPort;
  private String minecraftVersion;
  private String serverSoftware;
  private Date activatedAt;
  private Date lastSeenAt;
  private Date updatedAt;
  private boolean active;
  private String notes;
}
