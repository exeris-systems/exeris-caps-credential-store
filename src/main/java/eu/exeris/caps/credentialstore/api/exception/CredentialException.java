package eu.exeris.caps.credentialstore.api.exception;

/**
 * Base exception for all credential-store domain errors.
 */
public class CredentialException extends RuntimeException {

    public CredentialException(String message) {
        super(message);
    }

    public CredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
