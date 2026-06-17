package dev.neuralabs.auth.crypto;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EERateLimiter {

    private static final int DEFAULT_REQUESTS_PER_MINUTE = 60;
    private static final int DEFAULT_BURST_SIZE = 10;
    private static final long CLEANUP_INTERVAL_MINUTES = 5;
    private static final long BUCKET_EXPIRY_MINUTES = 15;

    private final Map<String, TokenBucket> ipBuckets;
    private final Map<String, NonceTracker> nonceTrackers;
    private final ScheduledExecutorService cleanupScheduler;
    private final int requestsPerMinute;
    private final int burstSize;
    private final boolean enabled;

   
    private final AtomicLong totalRequests;
    private final AtomicLong blockedRequests;
    private final AtomicLong suspiciousActivity;

        public E2EERateLimiter(boolean enabled, int requestsPerMinute) {
        this.enabled = enabled;
        this.requestsPerMinute = requestsPerMinute > 0
            ? requestsPerMinute
            : DEFAULT_REQUESTS_PER_MINUTE;
        this.burstSize = Math.max(
            DEFAULT_BURST_SIZE,
            this.requestsPerMinute / 6
        );

        this.ipBuckets = new ConcurrentHashMap<>();
        this.nonceTrackers = new ConcurrentHashMap<>();
        this.totalRequests = new AtomicLong(0);
        this.blockedRequests = new AtomicLong(0);
        this.suspiciousActivity = new AtomicLong(0);

        this.cleanupScheduler = Executors.newSingleThreadScheduledExecutor(
            r -> {
                Thread t = new Thread(r, "E2EE-RateLimiter-Cleanup");
                t.setDaemon(true);
                return t;
            }
        );

        if (enabled) {
            scheduleCleanup();
            log.info(
                "E2EE Rate Limiter initialized (limit: {} req/min, burst: {})",
                this.requestsPerMinute,
                this.burstSize
            );
        } else {
            log.info("E2EE Rate Limiter disabled");
        }
    }

        public RateLimitResult checkLimit(String ipAddress, String nonce) {
        totalRequests.incrementAndGet();

        if (!enabled) {
            return new RateLimitResult(
                true,
                requestsPerMinute,
                requestsPerMinute,
                null
            );
        }

       
        if (ipAddress == null || ipAddress.isEmpty()) {
            log.warn("Rate limit check with empty IP address");
            return new RateLimitResult(
                false,
                0,
                requestsPerMinute,
                "Invalid IP address"
            );
        }

       
        TokenBucket bucket = ipBuckets.computeIfAbsent(ipAddress, k ->
            new TokenBucket(requestsPerMinute, burstSize)
        );

        if (!bucket.tryConsume()) {
            blockedRequests.incrementAndGet();
            log.warn(
                "Rate limit exceeded for IP: {} (requests: {}, limit: {})",
                ipAddress,
                bucket.getConsumedTokens(),
                requestsPerMinute
            );
            return new RateLimitResult(
                false,
                0,
                requestsPerMinute,
                "Rate limit exceeded. Please try again later."
            );
        }

       
        if (nonce != null && !nonce.isEmpty()) {
            NonceTracker tracker = nonceTrackers.computeIfAbsent(ipAddress, k ->
                new NonceTracker()
            );

            if (tracker.isNonceRepeated(nonce)) {
                suspiciousActivity.incrementAndGet();
                log.warn(
                    "Suspicious activity detected: Repeated nonce from IP: {} (nonce: {})",
                    ipAddress,
                    nonce.substring(0, Math.min(8, nonce.length()))
                );

               
                return new RateLimitResult(
                    true,
                    bucket.getRemainingTokens(),
                    requestsPerMinute,
                    "Warning: Repeated nonce detected"
                );
            }
        }

        return new RateLimitResult(
            true,
            bucket.getRemainingTokens(),
            requestsPerMinute,
            null
        );
    }

        public boolean isRateLimited(String ipAddress) {
        if (!enabled || ipAddress == null) {
            return false;
        }

        TokenBucket bucket = ipBuckets.get(ipAddress);
        return bucket != null && !bucket.hasTokens();
    }

        public int getRemainingRequests(String ipAddress) {
        if (!enabled || ipAddress == null) {
            return requestsPerMinute;
        }

        TokenBucket bucket = ipBuckets.get(ipAddress);
        return bucket != null ? bucket.getRemainingTokens() : requestsPerMinute;
    }

        public void resetLimit(String ipAddress) {
        if (ipAddress != null) {
            ipBuckets.remove(ipAddress);
            nonceTrackers.remove(ipAddress);
            log.info("Rate limit reset for IP: {}", ipAddress);
        }
    }

        public void resetAllLimits() {
        int ipCount = ipBuckets.size();
        int nonceCount = nonceTrackers.size();
        ipBuckets.clear();
        nonceTrackers.clear();
        log.info(
            "All rate limits reset ({} IPs, {} nonce trackers)",
            ipCount,
            nonceCount
        );
    }

        private void scheduleCleanup() {
        cleanupScheduler.scheduleAtFixedRate(
            this::cleanupExpiredBuckets,
            CLEANUP_INTERVAL_MINUTES,
            CLEANUP_INTERVAL_MINUTES,
            TimeUnit.MINUTES
        );
    }

        private void cleanupExpiredBuckets() {
        try {
            long now = System.currentTimeMillis();
            long expiryThreshold =
                now - TimeUnit.MINUTES.toMillis(BUCKET_EXPIRY_MINUTES);

            int removedBuckets = 0;
            int removedTrackers = 0;

           
            for (Map.Entry<String, TokenBucket> entry : ipBuckets.entrySet()) {
                if (entry.getValue().getLastAccessTime() < expiryThreshold) {
                    ipBuckets.remove(entry.getKey());
                    removedBuckets++;
                }
            }

           
            for (Map.Entry<
                String,
                NonceTracker
            > entry : nonceTrackers.entrySet()) {
                if (entry.getValue().getLastAccessTime() < expiryThreshold) {
                    nonceTrackers.remove(entry.getKey());
                    removedTrackers++;
                }
            }

            if (removedBuckets > 0 || removedTrackers > 0) {
                log.debug(
                    "Cleanup: Removed {} expired IP buckets and {} nonce trackers",
                    removedBuckets,
                    removedTrackers
                );
            }
        } catch (Exception e) {
            log.error("Error during rate limiter cleanup", e);
        }
    }

        public Map<String, Object> getStats() {
        return Map.of(
            "enabled",
            enabled,
            "requestsPerMinute",
            requestsPerMinute,
            "burstSize",
            burstSize,
            "totalRequests",
            totalRequests.get(),
            "blockedRequests",
            blockedRequests.get(),
            "suspiciousActivity",
            suspiciousActivity.get(),
            "blockedPercentage",
            totalRequests.get() > 0
                ? ((blockedRequests.get() * 100.0) / totalRequests.get())
                : 0.0,
            "trackedIPs",
            ipBuckets.size(),
            "trackedNonces",
            nonceTrackers.size()
        );
    }

        public boolean isEnabled() {
        return enabled;
    }

        public void shutdown() {
        cleanupScheduler.shutdown();
        try {
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }
            log.info("E2EE Rate Limiter shutdown complete");
        } catch (InterruptedException e) {
            cleanupScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

        private static class TokenBucket {

        private final int capacity;
        private final int refillRate;
        private final long refillIntervalMs;
        private int tokens;
        private long lastRefillTime;
        private long lastAccessTime;
        private final AtomicInteger consumedTokens;

        public TokenBucket(int refillRate, int capacity) {
            this.refillRate = refillRate;
            this.capacity = capacity;
            this.tokens = capacity;
            this.lastRefillTime = System.currentTimeMillis();
            this.lastAccessTime = System.currentTimeMillis();
            this.refillIntervalMs = TimeUnit.MINUTES.toMillis(1) / refillRate;
            this.consumedTokens = new AtomicInteger(0);
        }

        public synchronized boolean tryConsume() {
            refill();
            lastAccessTime = System.currentTimeMillis();

            if (tokens > 0) {
                tokens--;
                consumedTokens.incrementAndGet();
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long timePassed = now - lastRefillTime;
            int tokensToAdd = (int) (timePassed / refillIntervalMs);

            if (tokensToAdd > 0) {
                tokens = Math.min(capacity, tokens + tokensToAdd);
                lastRefillTime = now;
            }
        }

        public synchronized int getRemainingTokens() {
            refill();
            return tokens;
        }

        public synchronized boolean hasTokens() {
            refill();
            return tokens > 0;
        }

        public long getLastAccessTime() {
            return lastAccessTime;
        }

        public int getConsumedTokens() {
            return consumedTokens.get();
        }
    }

        private static class NonceTracker {

        private final Map<String, Long> recentNonces;
        private long lastAccessTime;
        private static final long NONCE_TRACKING_WINDOW_MS =
            TimeUnit.MINUTES.toMillis(5);

        public NonceTracker() {
            this.recentNonces = new ConcurrentHashMap<>();
            this.lastAccessTime = System.currentTimeMillis();
        }

        public boolean isNonceRepeated(String nonce) {
            lastAccessTime = System.currentTimeMillis();
            cleanupOldNonces();

            Long previousUse = recentNonces.put(nonce, lastAccessTime);
            return previousUse != null;
        }

        private void cleanupOldNonces() {
            long threshold =
                System.currentTimeMillis() - NONCE_TRACKING_WINDOW_MS;
            recentNonces
                .entrySet()
                .removeIf(entry -> entry.getValue() < threshold);
        }

        public long getLastAccessTime() {
            return lastAccessTime;
        }
    }

        public static class RateLimitResult {

        private final boolean allowed;
        private final int remainingRequests;
        private final int limit;
        private final String message;

        public RateLimitResult(
            boolean allowed,
            int remainingRequests,
            int limit,
            String message
        ) {
            this.allowed = allowed;
            this.remainingRequests = remainingRequests;
            this.limit = limit;
            this.message = message;
        }

        public boolean isAllowed() {
            return allowed;
        }

        public int getRemainingRequests() {
            return remainingRequests;
        }

        public int getLimit() {
            return limit;
        }

        public String getMessage() {
            return message;
        }

        public boolean hasWarning() {
            return message != null && !message.isEmpty();
        }

        @Override
        public String toString() {
            return String.format(
                "RateLimitResult{allowed=%s, remaining=%d/%d, message='%s'}",
                allowed,
                remainingRequests,
                limit,
                message
            );
        }
    }
}
