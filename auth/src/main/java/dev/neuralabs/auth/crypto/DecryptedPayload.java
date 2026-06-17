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
public class DecryptedPayload {

        @JsonProperty("data")
    private String data;

        @JsonProperty("nonce")
    private String nonce;

        @JsonProperty("timestamp")
    private Long timestamp;

        @JsonProperty("senderId")
    private String senderId;

        public boolean isValid() {
        return data != null && !data.isEmpty() &&
               nonce != null && !nonce.isEmpty() &&
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

        public boolean isTimestampValid(long maxDiffMs) {
        if (timestamp == null) {
            return false;
        }
        long currentTime = System.currentTimeMillis();
        long diff = Math.abs(currentTime - timestamp);
        return diff <= maxDiffMs;
    }
}
