package com.sentrix.security.encryption

import android.util.Base64
import java.nio.ByteBuffer
import javax.crypto.SecretKey

/**
 * SentriX Encryption Validator
 *
 * Centralized validation component for the SentriX encryption subsystem.
 *
 * Responsibilities:
 *
 * - Validate encryption keys.
 * - Validate encrypted payload structure.
 * - Validate Base64 encoded encrypted data.
 * - Validate payload versions.
 * - Validate AES-GCM IV sizes.
 * - Validate authentication-tag requirements.
 * - Validate database encrypted values.
 * - Validate file encryption headers.
 * - Validate encryption input data.
 * - Validate encryption subsystem readiness.
 *
 * This class DOES NOT:
 *
 * - Encrypt data.
 * - Decrypt data.
 * - Generate keys.
 * - Store keys.
 * - Access databases.
 * - Perform network operations.
 *
 * It only validates cryptographic inputs and encryption metadata.
 *
 * Architecture:
 *
 *      EncryptionService
 *             │
 *             ▼
 *      EncryptionValidator
 *             │
 *       ┌─────┴─────┐
 *       ▼           ▼
 * Payload        Key Validation
 * Validation
 *
 * Security principle:
 *
 *      Validate → Process → Verify
 */
object EncryptionValidator {

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /**
     * Expected AES algorithm.
     */
    private const val AES_ALGORITHM = "AES"

    /**
     * Expected AES key size.
     */
    private const val AES_KEY_SIZE_BITS = 256

    /**
     * Expected AES-GCM IV size.
     */
    private const val GCM_IV_SIZE =
        EncryptionEngine.IV_SIZE

    /**
     * Expected GCM authentication tag size.
     */
    private const val GCM_TAG_LENGTH_BITS =
        EncryptionEngine.GCM_TAG_LENGTH

    /**
     * Authentication tag size in bytes.
     */
    private const val GCM_TAG_LENGTH_BYTES =
        GCM_TAG_LENGTH_BITS / Byte.SIZE_BITS

    /**
     * Current generic encryption payload version.
     */
    private const val CURRENT_PAYLOAD_VERSION = 1

    /**
     * Current database encryption prefix.
     *
     * Must remain synchronized with DatabaseEncryptionManager.
     */
    private const val DATABASE_PREFIX = "SXDB1:"

    /**
     * Current database format version.
     */
    private const val DATABASE_VERSION = 1

    /**
     * Current encrypted-file format version.
     */
    private const val FILE_FORMAT_VERSION: Byte = 1

    /**
     * Minimum plaintext size.
     *
     * SentriX does not encrypt empty values through its standard
     * data-encryption APIs.
     */
    private const val MIN_PLAINTEXT_SIZE = 1

    // -------------------------------------------------------------------------
    // General Validation
    // -------------------------------------------------------------------------

    /**
     * Validates that a plaintext String is suitable for encryption.
     */
    fun validatePlainText(
        plainText: String
    ): ValidationResult {

        if (plainText.isEmpty()) {

            return ValidationResult.Invalid(
                code = EncryptionValidationCode.EMPTY_INPUT,
                message = "Plaintext cannot be empty."
            )
        }

        return ValidationResult.Valid
    }

    /**
     * Validates a plaintext ByteArray.
     */
    fun validatePlainText(
        data: ByteArray
    ): ValidationResult {

        if (data.isEmpty()) {

            return ValidationResult.Invalid(
                code = EncryptionValidationCode.EMPTY_INPUT,
                message = "Plaintext data cannot be empty."
            )
        }

        return ValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Secret Key Validation
    // -------------------------------------------------------------------------

    /**
     * Validates an AES SecretKey.
     *
     * Android Keystore-backed keys may intentionally return null from
     * SecretKey.getEncoded(), therefore the raw key material is never
     * inspected here.
     */
    fun validateSecretKey(
        secretKey: SecretKey?
    ): ValidationResult {

        if (secretKey == null) {

            return ValidationResult.Invalid(
                code = EncryptionValidationCode.KEY_MISSING,
                message = "Encryption key is unavailable."
            )
        }

        if (
            !secretKey.algorithm.equals(
                AES_ALGORITHM,
                ignoreCase = true
            )
        ) {

            return ValidationResult.Invalid(
                code = EncryptionValidationCode.INVALID_KEY_ALGORITHM,
                message = "Encryption key must use AES."
            )
        }

        /**
         * For Android Keystore-backed keys, getEncoded() can return null.
         *
         * Therefore this validator does not reject such keys merely
         * because the raw material is unavailable.
         */
        return ValidationResult.Valid
    }

    /**
     * Validates the currently configured SentriX master key.
     */
    fun validateMasterKey(): ValidationResult {

        return try {

            when (
                val result =
                    EncryptionKeyManager.validateMasterKey()
            ) {

                is KeyValidationResult.Valid -> {
                    ValidationResult.Valid
                }

                is KeyValidationResult.Invalid -> {
                    ValidationResult.Invalid(
                        code =
                            EncryptionValidationCode.INVALID_KEY,
                        message = result.reason
                    )
                }
            }

        } catch (exception: Exception) {

            ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.KEY_UNAVAILABLE,
                message =
                    "Unable to validate SentriX master key.",
                cause = exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Base64 Validation
    // -------------------------------------------------------------------------

    /**
     * Validates whether a String is a valid Base64 encoded value.
     */
    fun validateBase64(
        value: String?
    ): ValidationResult {

        if (value.isNullOrBlank()) {

            return ValidationResult.Invalid(
                code = EncryptionValidationCode.EMPTY_INPUT,
                message = "Base64 value cannot be empty."
            )
        }

        return try {

            val decoded =
                Base64.decode(
                    value,
                    Base64.NO_WRAP
                )

            if (decoded.isEmpty()) {

                ValidationResult.Invalid(
                    code =
                        EncryptionValidationCode.INVALID_PAYLOAD,
                    message =
                        "Base64 value decodes to empty data."
                )

            } else {

                ValidationResult.Valid
            }

        } catch (exception: IllegalArgumentException) {

            ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_BASE64,
                message =
                    "Value is not valid Base64.",
                cause = exception
            )
        }
    }

    /**
     * Decodes Base64 after validation.
     */
    fun decodeBase64(
        value: String
    ): ValidationResultWithData<ByteArray> {

        val validation =
            validateBase64(
                value
            )

        if (
            validation !is ValidationResult.Valid
        ) {

            return ValidationResultWithData.Invalid(
                validation
            )
        }

        return try {

            ValidationResultWithData.Valid(
                Base64.decode(
                    value,
                    Base64.NO_WRAP
                )
            )

        } catch (exception: Exception) {

            ValidationResultWithData.Invalid(
                ValidationResult.Invalid(
                    code =
                        EncryptionValidationCode.INVALID_BASE64,
                    message =
                        "Unable to decode Base64 data.",
                    cause = exception
                )
            )
        }
    }

    // -------------------------------------------------------------------------
    // Encrypted Payload Validation
    // -------------------------------------------------------------------------

    /**
     * Validates a raw AES-GCM encrypted payload.
     *
     * Expected structure:
     *
     *      [IV][Ciphertext + Authentication Tag]
     *
     * This validates structure only.
     *
     * It does NOT prove that the ciphertext is authentic.
     * Authentication is performed by AES-GCM during decryption.
     */
    fun validateCryptographicPayload(
        payload: ByteArray?
    ): ValidationResult {

        if (payload == null || payload.isEmpty()) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.EMPTY_INPUT,
                message =
                    "Encrypted payload cannot be empty."
            )
        }

        val minimumSize =
            GCM_IV_SIZE +
                    GCM_TAG_LENGTH_BYTES +
                    MIN_PLAINTEXT_SIZE

        if (payload.size < minimumSize) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.PAYLOAD_TOO_SMALL,
                message =
                    "Encrypted payload is too small."
            )
        }

        val iv =
            payload.copyOfRange(
                0,
                GCM_IV_SIZE
            )

        return validateIv(
            iv
        )
    }

    /**
     * Validates a complete versioned SentriX payload.
     *
     * Expected:
     *
     *      [Version][IV][Ciphertext + Authentication Tag]
     */
    fun validateVersionedPayload(
        payload: ByteArray?
    ): ValidationResult {

        if (payload == null || payload.isEmpty()) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.EMPTY_INPUT,
                message =
                    "Versioned payload cannot be empty."
            )
        }

        val minimumSize =
            1 +
                    GCM_IV_SIZE +
                    GCM_TAG_LENGTH_BYTES +
                    MIN_PLAINTEXT_SIZE

        if (payload.size < minimumSize) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.PAYLOAD_TOO_SMALL,
                message =
                    "Versioned encryption payload is too small."
            )
        }

        val version =
            payload[0].toInt()

        val versionResult =
            validatePayloadVersion(
                version
            )

        if (
            versionResult !is ValidationResult.Valid
        ) {
            return versionResult
        }

        val cryptographicPayload =
            payload.copyOfRange(
                1,
                payload.size
            )

        return validateCryptographicPayload(
            cryptographicPayload
        )
    }

    // -------------------------------------------------------------------------
    // Payload Version Validation
    // -------------------------------------------------------------------------

    /**
     * Validates a SentriX encryption payload version.
     */
    fun validatePayloadVersion(
        version: Int
    ): ValidationResult {

        if (version <= 0) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_VERSION,
                message =
                    "Encryption payload version is invalid."
            )
        }

        if (
            version > CURRENT_PAYLOAD_VERSION
        ) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.UNSUPPORTED_VERSION,
                message =
                    "Encryption payload version is not supported."
            )
        }

        return ValidationResult.Valid
    }

    /**
     * Extracts the version from a versioned payload.
     */
    fun extractPayloadVersion(
        payload: ByteArray
    ): ValidationResultWithData<Int> {

        if (payload.isEmpty()) {

            return ValidationResultWithData.Invalid(
                ValidationResult.Invalid(
                    code =
                        EncryptionValidationCode.EMPTY_INPUT,
                    message =
                        "Payload cannot be empty."
                )
            )
        }

        val version =
            payload[0].toInt()

        val validation =
            validatePayloadVersion(
                version
            )

        return if (
            validation is ValidationResult.Valid
        ) {

            ValidationResultWithData.Valid(
                version
            )

        } else {

            ValidationResultWithData.Invalid(
                validation
            )
        }
    }

    // -------------------------------------------------------------------------
    // IV Validation
    // -------------------------------------------------------------------------

    /**
     * Validates an AES-GCM initialization vector.
     */
    fun validateIv(
        iv: ByteArray?
    ): ValidationResult {

        if (iv == null || iv.isEmpty()) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_IV,
                message =
                    "Initialization vector cannot be empty."
            )
        }

        if (iv.size != GCM_IV_SIZE) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_IV,
                message =
                    "Invalid AES-GCM initialization vector size."
            )
        }

        return ValidationResult.Valid
    }

    /**
     * Extracts and validates the IV from an encrypted payload.
     */
    fun extractIv(
        payload: ByteArray
    ): ValidationResultWithData<ByteArray> {

        val validation =
            validateCryptographicPayload(
                payload
            )

        if (
            validation !is ValidationResult.Valid
        ) {

            return ValidationResultWithData.Invalid(
                validation
            )
        }

        val iv =
            payload.copyOfRange(
                0,
                GCM_IV_SIZE
            )

        return ValidationResultWithData.Valid(
            iv
        )
    }

    // -------------------------------------------------------------------------
    // Authentication Tag Validation
    // -------------------------------------------------------------------------

    /**
     * Validates the minimum ciphertext size required for the
     * authentication tag.
     *
     * This is only structural validation.
     */
    fun validateAuthenticationTagSpace(
        payload: ByteArray
    ): ValidationResult {

        if (
            payload.size <
            GCM_IV_SIZE +
            GCM_TAG_LENGTH_BYTES +
            1
        ) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_AUTH_TAG,
                message =
                    "Encrypted payload does not contain sufficient authentication data."
            )
        }

        return ValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Database Encryption Validation
    // -------------------------------------------------------------------------

    /**
     * Validates a SentriX database-encrypted value.
     *
     * Expected format:
     *
     *      SXDB1:<Base64 encrypted payload>
     */
    fun validateDatabaseValue(
        value: String?
    ): ValidationResult {

        if (value.isNullOrBlank()) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.EMPTY_INPUT,
                message =
                    "Database encrypted value cannot be empty."
            )
        }

        if (
            !value.startsWith(
                DATABASE_PREFIX
            )
        ) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_DATABASE_FORMAT,
                message =
                    "Database value is not a SentriX encrypted value."
            )
        }

        val payload =
            value.removePrefix(
                DATABASE_PREFIX
            )

        val base64Validation =
            validateBase64(
                payload
            )

        if (
            base64Validation !is ValidationResult.Valid
        ) {
            return base64Validation
        }

        return try {

            val decoded =
                Base64.decode(
                    payload,
                    Base64.NO_WRAP
                )

            validateVersionedPayload(
                decoded
            )

        } catch (exception: Exception) {

            ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_DATABASE_FORMAT,
                message =
                    "Invalid encrypted database payload.",
                cause = exception
            )
        }
    }

    /**
     * Validates a database encryption version.
     */
    fun validateDatabaseVersion(
        version: Int
    ): ValidationResult {

        return if (
            version in 1..DATABASE_VERSION
        ) {

            ValidationResult.Valid

        } else {

            ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.UNSUPPORTED_VERSION,
                message =
                    "Unsupported database encryption version."
            )
        }
    }

    // -------------------------------------------------------------------------
    // File Encryption Validation
    // -------------------------------------------------------------------------

    /**
     * Validates an encrypted SentriX file header.
     *
     * Expected header:
     *
     *      [Version][12-byte IV]
     */
    fun validateFileHeader(
        header: ByteArray?
    ): ValidationResult {

        val requiredHeaderSize =
            1 +
                    GCM_IV_SIZE

        if (
            header == null ||
            header.size < requiredHeaderSize
        ) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.INVALID_FILE_HEADER,
                message =
                    "Encrypted file header is invalid."
            )
        }

        val version =
            header[0].toInt()

        if (
            version !=
            FILE_FORMAT_VERSION.toInt()
        ) {

            return ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.UNSUPPORTED_VERSION,
                message =
                    "Unsupported encrypted file version."
            )
        }

        val iv =
            header.copyOfRange(
                1,
                requiredHeaderSize
            )

        return validateIv(
            iv
        )
    }

    /**
     * Reads the IV from a valid file header.
     */
    fun extractFileIv(
        header: ByteArray
    ): ValidationResultWithData<ByteArray> {

        val validation =
            validateFileHeader(
                header
            )

        if (
            validation !is ValidationResult.Valid
        ) {

            return ValidationResultWithData.Invalid(
                validation
            )
        }

        val iv =
            header.copyOfRange(
                1,
                1 + GCM_IV_SIZE
            )

        return ValidationResultWithData.Valid(
            iv
        )
    }

    // -------------------------------------------------------------------------
    // Key Store Validation
    // -------------------------------------------------------------------------

    /**
     * Validates that the SentriX encryption key store is operational.
     */
    fun validateKeyStore(): ValidationResult {

        return try {

            val result =
                EncryptionKeyManager
                    .validateMasterKey()

            when (result) {

                is KeyValidationResult.Valid -> {
                    ValidationResult.Valid
                }

                is KeyValidationResult.Invalid -> {
                    ValidationResult.Invalid(
                        code =
                            EncryptionValidationCode.INVALID_KEY,
                        message =
                            result.reason
                    )
                }
            }

        } catch (exception: Exception) {

            ValidationResult.Invalid(
                code =
                    EncryptionValidationCode.KEY_UNAVAILABLE,
                message =
                    "SentriX encryption key store is unavailable.",
                cause = exception
            )
        }
    }

    // -------------------------------------------------------------------------
    // Complete Encryption Readiness Validation
    // -------------------------------------------------------------------------

    /**
     * Performs a complete readiness check before encryption/decryption.
     *
     * This checks the encryption key configuration but does not perform
     * an actual encryption/decryption operation.
     */
    fun validateEncryptionReadiness(): ValidationResult {

        val keyResult =
            validateKeyStore()

        if (
            keyResult !is ValidationResult.Valid
        ) {
            return keyResult
        }

        return ValidationResult.Valid
    }

    // -------------------------------------------------------------------------
    // Utility Validation
    // -------------------------------------------------------------------------

    /**
     * Validates that a byte array contains enough data for a GCM
     * cryptographic payload.
     */
    fun hasMinimumCryptographicSize(
        data: ByteArray
    ): Boolean {

        return data.size >=
                GCM_IV_SIZE +
                GCM_TAG_LENGTH_BYTES +
                MIN_PLAINTEXT_SIZE
    }

    /**
     * Returns the current encryption payload version.
     */
    fun getCurrentPayloadVersion(): Int {
        return CURRENT_PAYLOAD_VERSION
    }

    /**
     * Returns the current database encryption version.
     */
    fun getDatabaseEncryptionVersion(): Int {
        return DATABASE_VERSION
    }

    /**
     * Returns the current encrypted-file version.
     */
    fun getFileEncryptionVersion(): Int {
        return FILE_FORMAT_VERSION.toInt()
    }

    /**
     * Returns the expected AES-GCM IV size.
     */
    fun getIvSize(): Int {
        return GCM_IV_SIZE
    }

    /**
     * Returns the authentication tag size in bits.
     */
    fun getAuthenticationTagLength(): Int {
        return GCM_TAG_LENGTH_BITS
    }
}

/**
 * General result returned by EncryptionValidator.
 */
sealed class ValidationResult {

    /**
     * Validation succeeded.
     */
    data object Valid : ValidationResult()

    /**
     * Validation failed.
     *
     * @param code Machine-readable validation category.
     * @param message Safe diagnostic description.
     * @param cause Optional internal exception.
     */
    data class Invalid(
        val code: EncryptionValidationCode,
        val message: String,
        val cause: Throwable? = null
    ) : ValidationResult()
}

/**
 * Validation result that also contains validated data.
 *
 * Used when validation needs to produce:
 *
 * - Decoded Base64 data.
 * - Payload version.
 * - Extracted IV.
 */
sealed class ValidationResultWithData<T> {

    /**
     * Validation succeeded and contains validated data.
     */
    data class Valid<T>(
        val data: T
    ) : ValidationResultWithData<T>()

    /**
     * Validation failed.
     */
    data class Invalid<T>(
        val result: ValidationResult.Invalid
    ) : ValidationResultWithData<T>()
}

/**
 * Machine-readable encryption validation codes.
 *
 * Keeping validation codes separate from messages allows the SentriX
 * application to make decisions based on the code rather than parsing
 * human-readable strings.
 */
enum class EncryptionValidationCode {

    /**
     * Input data was empty.
     */
    EMPTY_INPUT,

    /**
     * Encryption key is completely unavailable.
     */
    KEY_MISSING,

    /**
     * Encryption key exists but cannot currently be accessed.
     */
    KEY_UNAVAILABLE,

    /**
     * Encryption key is not AES.
     */
    INVALID_KEY_ALGORITHM,

    /**
     * Encryption key failed general validation.
     */
    INVALID_KEY,

    /**
     * Base64 data is malformed.
     */
    INVALID_BASE64,

    /**
     * Encrypted payload is malformed.
     */
    INVALID_PAYLOAD,

    /**
     * Payload does not contain enough data.
     */
    PAYLOAD_TOO_SMALL,

    /**
     * AES-GCM IV is missing or has an incorrect size.
     */
    INVALID_IV,

    /**
     * Authentication tag data is structurally insufficient.
     */
    INVALID_AUTH_TAG,

    /**
     * Encryption format version is invalid.
     */
    INVALID_VERSION,

    /**
     * Encryption format version is newer than supported.
     */
    UNSUPPORTED_VERSION,

    /**
     * Database encryption format is malformed.
     */
    INVALID_DATABASE_FORMAT,

    /**
     * Encrypted-file header is malformed.
     */
    INVALID_FILE_HEADER
}
