package com.sentrix.security.sslpinning

import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * PublicKeyPinValidator
 *
 * Validates cryptographic public keys against SentriX SHA-256
 * public-key pins.
 *
 * Pin format:
 *
 * sha256/<Base64(SHA-256(SubjectPublicKeyInfo))>
 *
 * The public key is hashed using its encoded SubjectPublicKeyInfo
 * representation.
 *
 * Responsibilities:
 *
 * - Calculate SHA-256 public-key pins.
 * - Validate a PublicKey against configured pins.
 * - Validate public keys extracted from X509 certificates.
 * - Validate multiple backup pins.
 * - Validate pin format.
 * - Compare pins using a constant-time comparison.
 * - Generate structured validation results.
 *
 * This class does NOT:
 *
 * - establish TLS connections.
 * - replace Android TrustManager.
 * - replace hostname verification.
 * - disable certificate validation.
 * - automatically trust an otherwise untrusted certificate.
 *
 * Actual TLS enforcement remains with the Android/OkHttp TLS
 * security stack.
 *
 * Architecture:
 *
 * X509Certificate
 *       │
 *       ▼
 *    PublicKey
 *       │
 *       ▼
 * PublicKeyPinValidator
 *       │
 *       ├── SHA-256
 *       ├── Base64
 *       └── Pin comparison
 *       │
 *       ▼
 * PublicKeyPinValidationResult
 */
class PublicKeyPinValidator {

    companion object {

        /**
         * SHA-256 algorithm.
         */
        private const val SHA_256 =
            "SHA-256"

        /**
         * OkHttp-compatible public-key pin prefix.
         */
        private const val SHA256_PREFIX =
            "sha256/"

        /**
         * SHA-256 digest length.
         */
        private const val SHA256_DIGEST_LENGTH =
            32

        /**
         * Base64 encoded SHA-256 length.
         */
        private const val SHA256_BASE64_LENGTH =
            44

        /**
         * Base64 validation pattern.
         */
        private const val BASE64_PATTERN =
            "^[A-Za-z0-9+/]{43}={1}$"
    }

    /**
     * Validates a raw PublicKey against configured pins.
     */
    fun validate(
        publicKey: PublicKey,
        pins: Set<String>
    ): PublicKeyPinValidationResult {

        if (pins.isEmpty()) {

            return PublicKeyPinValidationResult(
                valid = false,
                status =
                    PublicKeyPinValidationStatus.NO_PINS_CONFIGURED,
                calculatedPin = null,
                matchedPin = null,
                checkedPins = 0,
                publicKeyAlgorithm =
                    publicKey.algorithm,
                publicKeyFormat =
                    publicKey.format,
                message =
                    "No public-key pins were configured."
            )
        }

        val calculatedPin =
            try {

                calculatePin(
                    publicKey
                )

            } catch (exception: Exception) {

                return PublicKeyPinValidationResult(
                    valid = false,
                    status =
                        PublicKeyPinValidationStatus.HASH_CALCULATION_FAILED,
                    calculatedPin = null,
                    matchedPin = null,
                    checkedPins = pins.size,
                    publicKeyAlgorithm =
                        publicKey.algorithm,
                    publicKeyFormat =
                        publicKey.format,
                    message =
                        "Unable to calculate the public-key pin.",
                    errorType =
                        exception.javaClass.simpleName
                )
            }

        val normalizedPins =
            pins
                .map {
                    it.trim()
                }
                .filter {
                    isValidPinFormat(it)
                }
                .toSet()

        if (normalizedPins.isEmpty()) {

            return PublicKeyPinValidationResult(
                valid = false,
                status =
                    PublicKeyPinValidationStatus.NO_VALID_PINS,
                calculatedPin =
                    calculatedPin,
                matchedPin = null,
                checkedPins = pins.size,
                publicKeyAlgorithm =
                    publicKey.algorithm,
                publicKeyFormat =
                    publicKey.format,
                message =
                    "No valid public-key pins were supplied."
            )
        }

        val matchedPin =
            normalizedPins.firstOrNull {
                constantTimeEquals(
                    calculatedPin,
                    it
                )
            }

        return if (matchedPin != null) {

            PublicKeyPinValidationResult(
                valid = true,
                status =
                    PublicKeyPinValidationStatus.PIN_MATCH,
                calculatedPin =
                    calculatedPin,
                matchedPin =
                    matchedPin,
                checkedPins =
                    normalizedPins.size,
                publicKeyAlgorithm =
                    publicKey.algorithm,
                publicKeyFormat =
                    publicKey.format,
                message =
                    "Public-key pin matched successfully."
            )

        } else {

            PublicKeyPinValidationResult(
                valid = false,
                status =
                    PublicKeyPinValidationStatus.PIN_MISMATCH,
                calculatedPin =
                    calculatedPin,
                matchedPin = null,
                checkedPins =
                    normalizedPins.size,
                publicKeyAlgorithm =
                    publicKey.algorithm,
                publicKeyFormat =
                    publicKey.format,
                message =
                    "Public-key pin did not match any configured pin."
            )
        }
    }

    /**
     * Validates the public key contained in an X509 certificate.
     */
    fun validateCertificateKey(
        certificate: X509Certificate,
        pins: Set<String>
    ): PublicKeyPinValidationResult {

        return validate(
            publicKey =
                certificate.publicKey,
            pins = pins
        )
    }

    /**
     * Calculates the OkHttp-compatible SHA-256 public-key pin.
     *
     * Hash input:
     *
     * publicKey.encoded
     *
     * The encoded value represents the SubjectPublicKeyInfo
     * structure.
     */
    fun calculatePin(
        publicKey: PublicKey
    ): String {

        val encodedKey =
            publicKey.encoded
                ?: throw IllegalArgumentException(
                    "Public key does not provide an encoded representation."
                )

        if (encodedKey.isEmpty()) {

            throw IllegalArgumentException(
                "Public key encoded representation is empty."
            )
        }

        val digest =
            MessageDigest
                .getInstance(
                    SHA_256
                )
                .digest(
                    encodedKey
                )

        return SHA256_PREFIX +
                encodeBase64(
                    digest
                )
    }

    /**
     * Calculates the raw SHA-256 digest of the public key.
     */
    fun calculateSha256(
        publicKey: PublicKey
    ): ByteArray {

        val encodedKey =
            publicKey.encoded
                ?: throw IllegalArgumentException(
                    "Public key does not provide an encoded representation."
                )

        return MessageDigest
            .getInstance(
                SHA_256
            )
            .digest(
                encodedKey
            )
    }

    /**
     * Calculates the Base64 encoded SHA-256 digest.
     *
     * This returns only the digest portion and does not include
     * the "sha256/" prefix.
     */
    fun calculateSha256Base64(
        publicKey: PublicKey
    ): String {

        return encodeBase64(
            calculateSha256(
                publicKey
            )
        )
    }

    /**
     * Checks whether a public key matches a single configured pin.
     */
    fun matchesPin(
        publicKey: PublicKey,
        expectedPin: String
    ): Boolean {

        val normalizedPin =
            expectedPin.trim()

        if (
            !isValidPinFormat(
                normalizedPin
            )
        ) {

            return false
        }

        val calculatedPin =
            try {

                calculatePin(
                    publicKey
                )

            } catch (_: Exception) {

                return false
            }

        return constantTimeEquals(
            calculatedPin,
            normalizedPin
        )
    }

    /**
     * Checks whether a public key matches at least one pin.
     */
    fun matchesAnyPin(
        publicKey: PublicKey,
        pins: Set<String>
    ): Boolean {

        if (pins.isEmpty()) {
            return false
        }

        val calculatedPin =
            try {

                calculatePin(
                    publicKey
                )

            } catch (_: Exception) {

                return false
            }

        return pins
            .asSequence()
            .map {
                it.trim()
            }
            .filter {
                isValidPinFormat(it)
            }
            .any {
                constantTimeEquals(
                    calculatedPin,
                    it
                )
            }
    }

    /**
     * Validates a collection of configured pins.
     */
    fun validatePinSet(
        pins: Set<String>
    ): PublicKeyPinSetValidationResult {

        if (pins.isEmpty()) {

            return PublicKeyPinSetValidationResult(
                valid = false,
                totalPins = 0,
                validPins = 0,
                invalidPins = emptyList(),
                duplicatePins = emptyList(),
                hasBackupPin = false,
                message =
                    "No public-key pins were supplied."
            )
        }

        val normalizedPins =
            pins.map {
                it.trim()
            }

        val validPins =
            normalizedPins.filter {
                isValidPinFormat(
                    it
                )
            }

        val invalidPins =
            normalizedPins.filter {
                !isValidPinFormat(
                    it
                )
            }

        val duplicatePins =
            normalizedPins
                .groupingBy {
                    it
                }
                .eachCount()
                .filter {
                    it.value > 1
                }
                .keys
                .toList()

        return PublicKeyPinSetValidationResult(
            valid =
                invalidPins.isEmpty() &&
                        duplicatePins.isEmpty(),
            totalPins =
                normalizedPins.size,
            validPins =
                validPins.size,
            invalidPins =
                invalidPins.map {
                    maskPin(it)
                },
            duplicatePins =
                duplicatePins.map {
                    maskPin(it)
                },
            hasBackupPin =
                validPins.size >= 2,
            message =
                if (
                    invalidPins.isEmpty() &&
                    duplicatePins.isEmpty()
                ) {
                    "Public-key pin set is valid."
                } else {
                    "Public-key pin set contains validation issues."
                }
        )
    }

    /**
     * Validates the format of an individual pin.
     *
     * Expected:
     *
     * sha256/<44-character Base64 SHA-256 digest>
     */
    fun isValidPinFormat(
        pin: String
    ): Boolean {

        val normalized =
            pin.trim()

        if (
            !normalized.startsWith(
                SHA256_PREFIX
            )
        ) {

            return false
        }

        val encoded =
            normalized.removePrefix(
                SHA256_PREFIX
            )

        if (
            encoded.length !=
            SHA256_BASE64_LENGTH
        ) {

            return false
        }

        if (
            !encoded.matches(
                Regex(
                    BASE64_PATTERN
                )
            )
        ) {

            return false
        }

        return try {

            val decoded =
                decodeBase64(
                    encoded
                )

            decoded.size ==
                    SHA256_DIGEST_LENGTH

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Returns public-key metadata.
     */
    fun getPublicKeyInfo(
        publicKey: PublicKey
    ): PublicKeyPinInfo {

        val encoded =
            publicKey.encoded

        return PublicKeyPinInfo(
            algorithm =
                publicKey.algorithm,
            format =
                publicKey.format,
            encodedLength =
                encoded?.size ?: 0,
            pin =
                calculatePin(
                    publicKey
                )
        )
    }

    /**
     * Compares two PublicKey instances by their encoded
     * SubjectPublicKeyInfo representation.
     */
    fun areKeysEquivalent(
        first: PublicKey,
        second: PublicKey
    ): Boolean {

        val firstEncoded =
            first.encoded
                ?: return false

        val secondEncoded =
            second.encoded
                ?: return false

        return constantTimeEquals(
            firstEncoded,
            secondEncoded
        )
    }

    /**
     * Checks whether a public key can be represented as an
     * encoded SubjectPublicKeyInfo structure.
     */
    fun isEncodable(
        publicKey: PublicKey
    ): Boolean {

        return try {

            val encoded =
                publicKey.encoded

            encoded != null &&
                    encoded.isNotEmpty()

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Normalizes pins for comparison.
     */
    fun normalizePins(
        pins: Set<String>
    ): Set<String> {

        return pins
            .map {
                it.trim()
            }
            .filter {
                isValidPinFormat(it)
            }
            .toSet()
    }

    /**
     * Encodes bytes as Base64 without line wrapping.
     */
    private fun encodeBase64(
        bytes: ByteArray
    ): String {

        return try {

            Base64
                .getEncoder()
                .encodeToString(
                    bytes
                )

        } catch (_: Throwable) {

            android.util.Base64
                .encodeToString(
                    bytes,
                    android.util.Base64.NO_WRAP
                )
        }
    }

    /**
     * Decodes Base64.
     */
    private fun decodeBase64(
        value: String
    ): ByteArray {

        return try {

            Base64
                .getDecoder()
                .decode(
                    value
                )

        } catch (_: Throwable) {

            android.util.Base64
                .decode(
                    value,
                    android.util.Base64.DEFAULT
                )
        }
    }

    /**
     * Constant-time comparison for byte arrays.
     */
    private fun constantTimeEquals(
        first: ByteArray,
        second: ByteArray
    ): Boolean {

        if (
            first.size !=
            second.size
        ) {

            return false
        }

        var result = 0

        for (
            index in first.indices
        ) {

            result =
                result or
                        (
                            first[index].toInt()
                                xor
                            second[index].toInt()
                        )
        }

        return result == 0
    }

    /**
     * Constant-time comparison for strings.
     */
    private fun constantTimeEquals(
        first: String,
        second: String
    ): Boolean {

        return constantTimeEquals(
            first.toByteArray(
                Charsets.UTF_8
            ),
            second.toByteArray(
                Charsets.UTF_8
            )
        )
    }

    /**
     * Masks a pin for diagnostic output.
     */
    private fun maskPin(
        pin: String
    ): String {

        if (
            pin.length <= 16
        ) {

            return "***"
        }

        return pin.take(12) +
                "..." +
                pin.takeLast(6)
    }
}

/**
 * Result of public-key pin validation.
 */
data class PublicKeyPinValidationResult(

    /**
     * Whether validation succeeded.
     */
    val valid: Boolean,

    /**
     * Validation status.
     */
    val status:
        PublicKeyPinValidationStatus,

    /**
     * Calculated public-key pin.
     */
    val calculatedPin: String?,

    /**
     * Matching configured pin.
     */
    val matchedPin: String?,

    /**
     * Number of valid pins checked.
     */
    val checkedPins: Int,

    /**
     * Public-key algorithm.
     */
    val publicKeyAlgorithm: String?,

    /**
     * Public-key encoding format.
     */
    val publicKeyFormat: String?,

    /**
     * Human-readable result.
     */
    val message: String,

    /**
     * Error class when hashing fails.
     */
    val errorType: String? = null
) {

    /**
     * Whether a pin matched.
     */
    val pinMatched: Boolean
        get() =
            status ==
                    PublicKeyPinValidationStatus.PIN_MATCH
}

/**
 * Public-key pin-set validation result.
 */
data class PublicKeyPinSetValidationResult(

    /**
     * Whether the complete pin set is valid.
     */
    val valid: Boolean,

    /**
     * Number of supplied pins.
     */
    val totalPins: Int,

    /**
     * Number of valid pins.
     */
    val validPins: Int,

    /**
     * Invalid pin values, masked.
     */
    val invalidPins: List<String>,

    /**
     * Duplicate pin values, masked.
     */
    val duplicatePins: List<String>,

    /**
     * Whether at least two valid pins are available.
     */
    val hasBackupPin: Boolean,

    /**
     * Human-readable result.
     */
    val message: String
)

/**
 * Public-key metadata.
 */
data class PublicKeyPinInfo(

    /**
     * Key algorithm.
     *
     * Examples:
     *
     * RSA
     * EC
     * Ed25519
     */
    val algorithm: String?,

    /**
     * Key encoding format.
     *
     * Usually X.509 for SubjectPublicKeyInfo.
     */
    val format: String?,

    /**
     * Encoded public-key size.
     */
    val encodedLength: Int,

    /**
     * Calculated SHA-256 pin.
     */
    val pin: String
)

/**
 * Public-key pin validation states.
 */
enum class PublicKeyPinValidationStatus {

    /**
     * Public key matched a configured pin.
     */
    PIN_MATCH,

    /**
     * Public key did not match configured pins.
     */
    PIN_MISMATCH,

    /**
     * No pins were supplied.
     */
    NO_PINS_CONFIGURED,

    /**
     * Pins were supplied but none were valid.
     */
    NO_VALID_PINS,

    /**
     * Public-key hash calculation failed.
     */
    HASH_CALCULATION_FAILED
}
