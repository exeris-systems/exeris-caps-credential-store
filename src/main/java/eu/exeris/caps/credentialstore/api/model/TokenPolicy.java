package eu.exeris.caps.credentialstore.api.model;

import java.time.Duration;

/**
 * Lifetimes of the single-use tokens this capability issues.
 *
 * @param verificationValidity how long an account-verification token stays usable; positive
 * @param resetValidity        how long a password-reset token stays usable; positive
 * @param issueCooldown        the minimum interval between two tokens of one kind for one account; a
 *                             request inside it issues nothing; positive
 */
public record TokenPolicy(Duration verificationValidity, Duration resetValidity, Duration issueCooldown) {

    public TokenPolicy {
        LockoutPolicy.requirePositive(verificationValidity, "verificationValidity");
        LockoutPolicy.requirePositive(resetValidity, "resetValidity");
        LockoutPolicy.requirePositive(issueCooldown, "issueCooldown");
    }

    /**
     * Verification tokens last 24 hours, reset tokens 15 minutes, and a new token of either kind is issued at
     * most once a minute per account.
     *
     * @return the default policy
     */
    public static TokenPolicy defaults() {
        return new TokenPolicy(Duration.ofHours(24), Duration.ofMinutes(15), Duration.ofSeconds(60));
    }
}
