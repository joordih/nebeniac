package dev.neuralabs.auth.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class RateLimiter {
    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final int capacity;
    private final long refillRateMs;
    private final long cleanupIntervalMs = 300000;
    private long lastCleanup = System.currentTimeMillis();

    public RateLimiter(int capacity, long refillRateMs) {
        this.capacity = capacity;
        this.refillRateMs = refillRateMs;
    }

    public boolean tryConsume(String key) {
        periodicCleanup();

        TokenBucket bucket = buckets.computeIfAbsent(key, k -> new TokenBucket(capacity, refillRateMs));
        return bucket.tryConsume();
    }

    private void periodicCleanup() {
        long now = System.currentTimeMillis();
        if (now - lastCleanup > cleanupIntervalMs) {
            buckets.entrySet().removeIf(entry ->
                now - entry.getValue().lastRefill.get() > cleanupIntervalMs
            );
            lastCleanup = now;
        }
    }

    private static class TokenBucket {
        private final int capacity;
        private final long refillRateMs;
        private final AtomicInteger tokens;
        private final AtomicLong lastRefill;

        TokenBucket(int capacity, long refillRateMs) {
            this.capacity = capacity;
            this.refillRateMs = refillRateMs;
            this.tokens = new AtomicInteger(capacity);
            this.lastRefill = new AtomicLong(System.currentTimeMillis());
        }

        synchronized boolean tryConsume() {
            refill();
            int current = tokens.get();
            if (current > 0) {
                tokens.decrementAndGet();
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long last = lastRefill.get();
            long elapsed = now - last;

            if (elapsed >= refillRateMs) {
                int tokensToAdd = (int) (elapsed / refillRateMs);
                int current = tokens.get();
                int newTokens = Math.min(capacity, current + tokensToAdd);
                tokens.set(newTokens);
                lastRefill.set(now);
            }
        }
    }

    public static class Factory {
        public static RateLimiter forLicenseVerification() {
            return new RateLimiter(10, 6000);
        }

        public static RateLimiter forMetadataRequests() {
            return new RateLimiter(30, 2000);
        }

        public static RateLimiter forAuthentication() {
            return new RateLimiter(5, 60000);
        }
    }
}
