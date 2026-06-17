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
import java.util.Map;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuditLog {
  @Id
  @ObjectId
  @JsonProperty("_id")
  private String id;
  private Date timestamp;
  private String level;
  private String event;
  private String licenseKey;
  private String clientId;
  private String clientIp;
  private boolean success;
  private String message;
  private Map<String, Object> details;
}
