package com.sentrix.core.exceptions

import java.security.GeneralSecurityException

/**
 * EncryptionException
 *
 * Base exception for all encryption,
 * decryption, key management, and
 * cryptographic operation failures
 * within SentriX.
 */
open class EncryptionException : GeneralSecurityException {

    constructor(
        message: String
    ) : super(message)

    constructor(
        message: String,
        cause: Throwable?
    ) : super(message, cause)
}

/**
 * Encryption operation failed.
 */
class EncryptionFailedException(
    message: String = "Encryption operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Decryption operation failed.
 */
class DecryptionFailedException(
    message: String = "Decryption operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Key generation failure.
 */
class KeyGenerationException(
    message: String = "Failed to generate cryptographic key.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Key retrieval failure.
 */
class KeyRetrievalException(
    message: String = "Unable to retrieve cryptographic key.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Key storage failure.
 */
class KeyStorageException(
    message: String = "Failed to securely store cryptographic key.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Key deletion failure.
 */
class KeyDeletionException(
    message: String = "Failed to delete cryptographic key.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Invalid encryption key.
 */
class InvalidKeyException(
    message: String = "Invalid encryption key."
) : EncryptionException(message)

/**
 * Missing encryption key.
 */
class MissingKeyException(
    message: String = "Encryption key not found."
) : EncryptionException(message)

/**
 * Key rotation failure.
 */
class KeyRotationException(
    message: String = "Key rotation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Certificate validation failure.
 */
class CertificateValidationException(
    message: String = "Certificate validation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Certificate generation failure.
 */
class CertificateGenerationException(
    message: String = "Certificate generation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Digital signature failure.
 */
class SignatureException(
    message: String = "Digital signature verification failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Hash generation failure.
 */
class HashingException(
    message: String = "Hash generation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Unsupported encryption algorithm.
 */
class UnsupportedAlgorithmException(
    message: String = "Unsupported encryption algorithm."
) : EncryptionException(message)

/**
 * Cipher initialization failure.
 */
class CipherInitializationException(
    message: String = "Failed to initialize cipher.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Secure random generation failure.
 */
class SecureRandomException(
    message: String = "Failed to generate secure random data.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Android Keystore failure.
 */
class KeystoreException(
    message: String = "Android Keystore operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Biometric-bound key failure.
 */
class BiometricKeyException(
    message: String = "Biometric protected key operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Data integrity validation failure.
 */
class IntegrityCheckException(
    message: String = "Data integrity validation failed."
) : EncryptionException(message)

/**
 * Tamper detection triggered.
 */
class TamperDetectionException(
    message: String = "Possible data tampering detected."
) : EncryptionException(message)

/**
 * Encrypted storage failure.
 */
class EncryptedStorageException(
    message: String = "Encrypted storage operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Token encryption failure.
 */
class TokenEncryptionException(
    message: String = "Failed to encrypt authentication token.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Database encryption failure.
 */
class DatabaseEncryptionException(
    message: String = "Database encryption failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * File encryption failure.
 */
class FileEncryptionException(
    message: String = "File encryption failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * File decryption failure.
 */
class FileDecryptionException(
    message: String = "File decryption failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)

/**
 * Secret management failure.
 */
class SecretManagementException(
    message: String = "Secret management operation failed.",
    cause: Throwable? = null
) : EncryptionException(message, cause)
