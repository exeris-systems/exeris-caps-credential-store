package eu.exeris.caps.credentialstore.api.exception;

/**
 * Thrown when a credential is created for a subject or a login identifier that already has one.
 *
 * <p>The exception does not say which of the two collided, and carries neither value. A caller that faces
 * an unauthenticated client answers this case exactly as it answers a successful registration, so the
 * response does not reveal whether an account exists.
 */
public class CredentialAlreadyExistsException extends CredentialException {

    public CredentialAlreadyExistsException() {
        super("A credential already exists for this subject or login identifier");
    }
}
