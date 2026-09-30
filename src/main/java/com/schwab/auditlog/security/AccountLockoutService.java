package com.schwab.auditlog.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sliding Window Account Lockout Service (SEC-02).
 * Locks a username for 15 minutes after 5 failed authentication attempts within a 15-minute window.
 */
@Component
public class AccountLockoutService {

    private static final int MAX_ATTEMPTS = 5;
    private static final long WINDOW_MILLIS = 15 * 60 * 1000L; // 15 minutes
    private static final long LOCKOUT_DURATION_MILLIS = 15 * 60 * 1000L; // 15 minutes

    private final Map<String, UserLockoutState> userStates = new ConcurrentHashMap<>();

    public boolean isLocked(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }
        UserLockoutState state = userStates.get(username.toLowerCase());
        if (state == null) {
            return false;
        }
        return state.isLocked();
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        if (username != null && !username.isBlank()) {
            UserLockoutState state = userStates.computeIfAbsent(username.toLowerCase(), k -> new UserLockoutState());
            state.recordFailure();
        }
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        if (username != null && !username.isBlank()) {
            UserLockoutState state = userStates.get(username.toLowerCase());
            if (state != null && !state.isLocked()) {
                state.reset();
            }
        }
    }

    public void resetLockout(String username) {
        if (username != null) {
            userStates.remove(username.toLowerCase());
        }
    }

    private static class UserLockoutState {
        private final List<Long> failureTimestamps = new ArrayList<>();
        private long lockedUntil = 0;

        public synchronized void recordFailure() {
            long now = System.currentTimeMillis();
            if (isLocked()) {
                return;
            }
            failureTimestamps.removeIf(ts -> (now - ts) > WINDOW_MILLIS);
            failureTimestamps.add(now);

            if (failureTimestamps.size() >= MAX_ATTEMPTS) {
                lockedUntil = now + LOCKOUT_DURATION_MILLIS;
            }
        }

        public synchronized boolean isLocked() {
            long now = System.currentTimeMillis();
            if (lockedUntil > 0) {
                if (now < lockedUntil) {
                    return true;
                } else {
                    lockedUntil = 0;
                    failureTimestamps.clear();
                    return false;
                }
            }
            return false;
        }

        public synchronized void reset() {
            failureTimestamps.clear();
            lockedUntil = 0;
        }
    }
}
