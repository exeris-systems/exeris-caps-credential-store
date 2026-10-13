package eu.exeris.caps.credentialstore.api.exception;

/**
 * Thrown when a newly supplied password is identical to the currently stored password.
 */
public class SamePasswordException extends CredentialException {

    public SamePasswordException(String message) {
        super(message);
    }

    public SamePasswordException(String message, Throwable cause) {
        super(message, cause);
    }
}
