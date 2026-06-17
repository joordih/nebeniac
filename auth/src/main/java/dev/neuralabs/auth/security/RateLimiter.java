package dev.neuralabs.auth.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Token bucket rate limiter implementation for protecting endpoints from abuse.
 * SECURITY: Prevents brute force attacks and DoS attempts.
 */
public class RateLimiter {

    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final int capacity;
    private final long refillRateMs;
    private final long cleanupIntervalMs = 300000; // 5 minutes
    private long lastCleanup = System.currentTimeMillis();

    /**
     * Creates a rate limiter with token bucket algorithm.
     * 
     * @param capacity Maximum number of tokens (requests) allowed
     * @param refillRateMs Time in milliseconds to refill one token
     */
    public RateLimiter(int capacity, long refillRateMs) {
        this.capacity = capacity;
        this.refillRateMs = refillRateMs;
    }

    /**
     * Attempts to consume a token for the given key.
     * 
     * @param key Identifier (e.g., IP address, license key, user ID)
     * @return true if request is allowed, false if rate limit exceeded
     */
    public boolean tryConsume(String key) {
        periodicCleanup();
        
        TokenBucket bucket = buckets.computeIfAbsent(key, k -> new TokenBucket(capacity, refillRateMs));
        return bucket.tryConsume();
    }

    /**
     * Checks if a key is currently rate limited without consuming a token.
     */
    public boolean isRateLimited(String key) {
        TokenBucket bucket = buckets.get(key);
        return bucket != null && bucket.getAvailableTokens() <= 0;
    }

    /**
     * Gets remaining tokens for a key.
     */
    public int getRemainingTokens(String key) {
        TokenBucket bucket = buckets.get(key);
        return bucket != null ? bucket.getAvailableTokens() : capacity;
    }

    /**
     * Resets rate limit for a specific key.
     */
    public void reset(String key) {
        buckets.remove(key);
    }

    /**
     * Clears all rate limit data.
     */
    public void clear() {
        buckets.clear();
    }

    /**
     * Periodic cleanup of old buckets to prevent memory leaks.
     */
    private void periodicCleanup() {
        long now = System.currentTimeMillis();
        if (now - lastCleanup > cleanupIntervalMs) {
            buckets.entrySet().removeIf(entry -> 
                now - entry.getValue().lastRefill.get() > cleanupIntervalMs
            );
            lastCleanup = now;
        }
    }

    /**
     * Token bucket implementation for rate limiting.
     */
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

        synchronized int getAvailableTokens() {
            refill();
            return tokens.get();
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

    /**
     * Factory methods for common rate limiting scenarios.
     */
    public static class Factory {
        
        /**
         * Rate limiter for license verification: 10 requests per minute per IP.
         */
        public static RateLimiter forLicenseVerification() {
            return new RateLimiter(10, 6000); // 10 tokens, refill 1 every 6 seconds
        }

        /**
         * Rate limiter for metadata requests: 30 requests per minute per license.
         */
        public static RateLimiter forMetadataRequests() {
            return new RateLimiter(30, 2000); // 30 tokens, refill 1 every 2 seconds
        }

        /**
         * Rate limiter for plugin downloads: 5 downloads per hour per license.
         */
        public static RateLimiter forPluginDownloads() {
            return new RateLimiter(5, 720000); // 5 tokens, refill 1 every 12 minutes
        }

        /**
         * Strict rate limiter for authentication: 5 attempts per 5 minutes.
         */
        public static RateLimiter forAuthentication() {
            return new RateLimiter(5, 60000); // 5 tokens, refill 1 every minute
        }
    }
}
