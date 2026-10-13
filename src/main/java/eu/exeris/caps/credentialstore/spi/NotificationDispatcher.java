package eu.exeris.caps.credentialstore.spi;

import java.util.UUID;

/**
 * Capability SPI contract for dispatching verification and reset notification messages.
 *
 * @since 0.1.0
 */
public interface NotificationDispatcher {

    /**
     * Dispatches an account verification notification containing the raw single-use token.
     *
     * @param subjectId identity subject identifier
     * @param recipientEmail recipient email address
     * @param rawToken raw single-use verification token
     */
    void sendVerificationToken(UUID subjectId, String recipientEmail, String rawToken);

    /**
     * Dispatches a credential recovery / password reset notification containing the raw single-use token.
     *
     * @param subjectId identity subject identifier
     * @param recipientEmail recipient email address
     * @param rawToken raw single-use reset token
     */
    void sendPasswordResetToken(UUID subjectId, String recipientEmail, String rawToken);
}
