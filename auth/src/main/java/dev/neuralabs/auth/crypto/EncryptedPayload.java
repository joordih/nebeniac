package dev.neuralabs.auth.crypto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EncryptedPayload {

        @JsonProperty("ciphertext")
    private String ciphertext;

        @JsonProperty("timestamp")
    private Long timestamp;

        @JsonProperty("version")
    private String version;

        @JsonProperty("senderId")
    private String senderId;

        @JsonProperty("nonce")
    private String nonce;

        public boolean isValid() {
        return ciphertext != null && !ciphertext.isEmpty() &&
               timestamp != null && timestamp > 0;
    }

        public long getAge() {
        if (timestamp == null) {
            return Long.MAX_VALUE;
        }
        return System.currentTimeMillis() - timestamp;
    }

        public boolean isExpired(long maxAgeMs) {
        return getAge() > maxAgeMs;
    }
}
