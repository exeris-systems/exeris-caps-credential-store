package eu.exeris.caps.credentialstore.api.exception;

/**
 * Thrown when a verification or reset token is invalid, expired, or already consumed.
 */
public class InvalidTokenException extends CredentialException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
