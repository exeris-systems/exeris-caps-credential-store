package eu.exeris.caps.credentialstore.api.exception;

/**
 * Thrown when credentials are invalid or subject has no recorded credential.
 */
public class InvalidCredentialException extends CredentialException {

    public InvalidCredentialException(String message) {
        super(message);
    }

    public InvalidCredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
