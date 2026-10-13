package eu.exeris.caps.credentialstore.api.exception;

import java.time.Duration;
import java.util.Objects;

/**
 * Thrown when a token generation request is rejected because the cooldown period has not elapsed.
 */
public class TokenCooldownException extends CredentialException {

    private final Duration remainingCooldown;

    public TokenCooldownException(String message, Duration remainingCooldown) {
        super(message);
        this.remainingCooldown = Objects.requireNonNull(remainingCooldown, "remainingCooldown must not be null");
    }

    public Duration remainingCooldown() {
        return remainingCooldown;
    }
}
