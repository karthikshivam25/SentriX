package com.sentrix.security.sslpinning

import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * CertificatePinValidator
 *
 * Performs certificate/public-key pin validation for SentriX.
 *
 * Responsibilities:
 *
 * - Validate an X509 certificate against configured SHA-256 pins.
 * - Calculate the SHA-256 digest of the certificate public key.
 * - Validate a complete certificate chain.
 * - Support backup pins.
 * - Avoid exposing complete certificate material in logs.
 * - Return structured validation results.
 *
 * Pin format:
 *
 * sha256/<Base64(SHA-256(SubjectPublicKeyInfo))>
 *
 * This is the same public-key pin format used by OkHttp's
 * CertificatePinner.
 *
 * IMPORTANT:
 *
 * This class is an additional validation component.
 *
 * It does NOT:
 *
 * - disable normal TLS validation.
 * - replace Android's TrustManager.
 * - replace hostname verification.
 * - accept an otherwise untrusted certificate.
 *
 * Normal TLS validation should happen first. This validator
 * determines whether a trusted certificate chain also satisfies
 * SentriX's configured pin policy.
 *
 * Architecture:
 *
 * TLS Handshake
 *      ↓
 * Android TrustManager
 *      ↓
 * Hostname Verification
 *      ↓
 * CertificatePinValidator
 *      ↓
 * SentriX Pinning Result
 */
class CertificatePinValidator {

    /**
     * SHA-256 digest algorithm.
     */
    private val sha256 =
        "SHA-256"

    /**
     * OkHttp-compatible certificate pin prefix.
     */
    private val sha256PinPrefix =
        "sha256/"

    /**
     * Validates a single X509 certificate against a set of pins.
     *
     * The certificate's SubjectPublicKeyInfo is hashed rather than
     * the entire DER-encoded certificate.
     *
     * This allows a new certificate to be issued for the same key
     * without changing the public-key pin.
     */
    fun validateCertificate(
        certificate: X509Certificate,
        pins: Set<String>
    ): CertificatePinValidationResult {

        if (pins.isEmpty()) {

            return CertificatePinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.NO_PINS_CONFIGURED,
                certificateSubject =
                    safeSubject(
                        certificate
                    ),
                matchedPin = null,
                certificatePin =
                    calculatePin(
                        certificate
                    ),
                checkedPins = 0,
                message =
                    "No certificate pins were configured."
            )
        }

        val normalizedPins =
            normalizePins(
                pins
            )

        val certificatePin =
            try {

                calculatePin(
                    certificate
                )

            } catch (exception: Exception) {

                return CertificatePinValidationResult(
                    valid = false,
                    status =
                        CertificatePinValidationStatus.HASH_CALCULATION_FAILED,
                    certificateSubject =
                        safeSubject(
                            certificate
                        ),
                    matchedPin = null,
                    certificatePin = null,
                    checkedPins =
                        normalizedPins.size,
                    message =
                        "Unable to calculate certificate public-key pin.",
                    errorType =
                        exception.javaClass.simpleName
                )
            }

        val matchedPin =
            normalizedPins.firstOrNull {
                constantTimeEquals(
                    it,
                    certificatePin
                )
            }

        return if (matchedPin != null) {

            CertificatePinValidationResult(
                valid = true,
                status =
                    CertificatePinValidationStatus.PIN_MATCH,
                certificateSubject =
                    safeSubject(
                        certificate
                    ),
                matchedPin =
                    matchedPin,
                certificatePin =
                    certificatePin,
                checkedPins =
                    normalizedPins.size,
                message =
                    "Certificate public-key pin matched."
            )

        } else {

            CertificatePinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.PIN_MISMATCH,
                certificateSubject =
                    safeSubject(
                        certificate
                    ),
                matchedPin = null,
                certificatePin =
                    certificatePin,
                checkedPins =
                    normalizedPins.size,
                message =
                    "Certificate public-key pin did not match any configured pin."
            )
        }
    }

    /**
     * Validates an entire X509 certificate chain.
     *
     * Any certificate in the chain may match a configured pin.
     *
     * This is useful when the application pins a leaf certificate
     * key or a controlled intermediate/backup key.
     */
    fun validateCertificateChain(
        certificateChain:
            List<X509Certificate>,
        pins: Set<String>
    ): CertificateChainPinValidationResult {

        if (certificateChain.isEmpty()) {

            return CertificateChainPinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.EMPTY_CERTIFICATE_CHAIN,
                matchedCertificateIndex = null,
                certificateResults = emptyList(),
                message =
                    "The certificate chain is empty."
            )
        }

        if (pins.isEmpty()) {

            return CertificateChainPinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.NO_PINS_CONFIGURED,
                matchedCertificateIndex = null,
                certificateResults = emptyList(),
                message =
                    "No certificate pins were configured."
            )
        }

        val results =
            certificateChain.mapIndexed { index, certificate ->

                index to
                    validateCertificate(
                        certificate = certificate,
                        pins = pins
                    )
            }

        val matched =
            results.firstOrNull {
                it.second.valid
            }

        return if (matched != null) {

            CertificateChainPinValidationResult(
                valid = true,
                status =
                    CertificatePinValidationStatus.PIN_MATCH,
                matchedCertificateIndex =
                    matched.first,
                certificateResults =
                    results.map {
                        it.second
                    },
                message =
                    "A certificate in the chain matched a configured pin."
            )

        } else {

            CertificateChainPinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.PIN_MISMATCH,
                matchedCertificateIndex = null,
                certificateResults =
                    results.map {
                        it.second
                    },
                message =
                    "No certificate in the chain matched the configured pins."
            )
        }
    }

    /**
     * Validates a generic Java Certificate.
     *
     * This is useful when the certificate comes directly from
     * an SSLSession or another Java networking API.
     */
    fun validateCertificate(
        certificate: Certificate,
        pins: Set<String>
    ): CertificatePinValidationResult {

        if (
            certificate !is X509Certificate
        ) {

            return CertificatePinValidationResult(
                valid = false,
                status =
                    CertificatePinValidationStatus.UNSUPPORTED_CERTIFICATE,
                certificateSubject = null,
                matchedPin = null,
                certificatePin = null,
                checkedPins = pins.size,
                message =
                    "The supplied certificate is not an X509Certificate."
            )
        }

        return validateCertificate(
            certificate = certificate,
            pins = pins
        )
    }

    /**
     * Calculates the OkHttp-compatible SHA-256 public-key pin.
     *
     * The hash input is:
     *
     * certificate.publicKey.encoded
     *
     * which represents the SubjectPublicKeyInfo structure.
     */
    fun calculatePin(
        certificate: X509Certificate
    ): String {

        val publicKeyBytes =
            certificate
                .publicKey
                .encoded

        val digest =
            MessageDigest
                .getInstance(
                    sha256
                )
                .digest(
                    publicKeyBytes
                )

        val encoded =
            encodeBase64(
                digest
            )

        return sha256PinPrefix +
                encoded
    }

    /**
     * Calculates the SHA-256 digest of a public key.
     *
     * Returns the raw digest bytes.
     */
    fun calculatePublicKeySha256(
        certificate: X509Certificate
    ): ByteArray {

        return MessageDigest
            .getInstance(
                sha256
            )
            .digest(
                certificate
                    .publicKey
                    .encoded
            )
    }

    /**
     * Returns the Base64-encoded public-key digest.
     */
    fun calculatePublicKeySha256Base64(
        certificate: X509Certificate
    ): String {

        return encodeBase64(
            calculatePublicKeySha256(
                certificate
            )
        )
    }

    /**
     * Validates whether a pin has the expected format.
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
                sha256PinPrefix
            )
        ) {

            return false
        }

        val encoded =
            normalized.removePrefix(
                sha256PinPrefix
            )

        /**
         * Decode and verify that the digest is exactly 32 bytes.
         */
        return try {

            val decoded =
                decodeBase64(
                    encoded
                )

            decoded.size == 32

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Validates a collection of pins.
     */
    fun validatePinSet(
        pins: Set<String>
    ): CertificatePinSetValidationResult {

        if (pins.isEmpty()) {

            return CertificatePinSetValidationResult(
                valid = false,
                totalPins = 0,
                validPins = 0,
                invalidPins = emptyList(),
                duplicatePins = emptyList(),
                hasBackupPin = false,
                message =
                    "No certificate pins were supplied."
            )
        }

        val normalizedPins =
            pins.map {
                it.trim()
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

        val validPinCount =
            normalizedPins.count {
                isValidPinFormat(
                    it
                )
            }

        return CertificatePinSetValidationResult(
            valid =
                invalidPins.isEmpty() &&
                        duplicatePins.isEmpty(),
            totalPins =
                normalizedPins.size,
            validPins =
                validPinCount,
            invalidPins =
                invalidPins.map {
                    maskPin(it)
                },
            duplicatePins =
                duplicatePins.map {
                    maskPin(it)
                },
            hasBackupPin =
                validPinCount >= 2,
            message =
                if (
                    invalidPins.isEmpty() &&
                    duplicatePins.isEmpty()
                ) {
                    "Certificate pin set is valid."
                } else {
                    "Certificate pin set contains validation issues."
                }
        )
    }

    /**
     * Compares an observed certificate against one configured pin.
     */
    fun matchesPin(
        certificate: X509Certificate,
        expectedPin: String
    ): Boolean {

        if (
            !isValidPinFormat(
                expectedPin
            )
        ) {

            return false
        }

        val actualPin =
            calculatePin(
                certificate
            )

        return constantTimeEquals(
            actualPin,
            expectedPin.trim()
        )
    }

    /**
     * Compares a certificate against multiple pins.
     */
    fun matchesAnyPin(
        certificate: X509Certificate,
        pins: Set<String>
    ): Boolean {

        if (pins.isEmpty()) {
            return false
        }

        val actualPin =
            calculatePin(
                certificate
            )

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
                    actualPin,
                    it
                )
            }
    }

    /**
     * Extracts useful certificate metadata without returning the
     * complete encoded certificate.
     */
    fun getCertificateInfo(
        certificate: X509Certificate
    ): CertificatePinCertificateInfo {

        return CertificatePinCertificateInfo(
            subject =
                safeSubject(
                    certificate
                ),
            issuer =
                safeIssuer(
                    certificate
                ),
            serialNumber =
                certificate.serialNumber
                    .toString(16),
            notBefore =
                certificate.notBefore
                    .time,
            notAfter =
                certificate.notAfter
                    .time,
            publicKeyAlgorithm =
                certificate
                    .publicKey
                    .algorithm,
            signatureAlgorithm =
                certificate
                    .sigAlgName,
            pin =
                calculatePin(
                    certificate
                )
        )
    }

    /**
     * Checks whether the certificate is currently within its
     * validity period.
     *
     * This is NOT a replacement for normal TLS certificate
     * validation.
     */
    fun isCertificateCurrentlyValid(
        certificate: X509Certificate,
        now: Long =
            System.currentTimeMillis()
    ): Boolean {

        return try {

            certificate.checkValidity(
                java.util.Date(
                    now
                )
            )

            true

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Normalizes a set of pins.
     */
    private fun normalizePins(
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
     * Base64 encoding compatible with Android and JVM.
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
     * Base64 decoding compatible with Android and JVM.
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
     * Constant-time string comparison.
     *
     * This avoids an early-exit comparison when comparing
     * already normalized pin strings.
     */
    private fun constantTimeEquals(
        first: String,
        second: String
    ): Boolean {

        val firstBytes =
            first
                .toByteArray(
                    Charsets.UTF_8
                )

        val secondBytes =
            second
                .toByteArray(
                    Charsets.UTF_8
                )

        if (
            firstBytes.size !=
            secondBytes.size
        ) {

            return false
        }

        var difference = 0

        for (
            index in firstBytes.indices
        ) {

            difference =
                difference or
                        (
                            firstBytes[index]
                                .toInt()
                                xor
                            secondBytes[index]
                                .toInt()
                        )
        }

        return difference == 0
    }

    /**
     * Safely obtains the certificate subject.
     */
    private fun safeSubject(
        certificate: X509Certificate
    ): String? {

        return try {

            certificate
                .subjectX500Principal
                .name

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Safely obtains the certificate issuer.
     */
    private fun safeIssuer(
        certificate: X509Certificate
    ): String? {

        return try {

            certificate
                .issuerX500Principal
                .name

        } catch (_: Exception) {

            null
        }
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
 * Result of validating one certificate.
 */
data class CertificatePinValidationResult(

    /**
     * Whether the certificate matched a configured pin.
     */
    val valid: Boolean,

    /**
     * Validation status.
     */
    val status:
        CertificatePinValidationStatus,

    /**
     * Certificate subject.
     */
    val certificateSubject: String?,

    /**
     * The configured pin that matched.
     */
    val matchedPin: String?,

    /**
     * Calculated certificate public-key pin.
     */
    val certificatePin: String?,

    /**
     * Number of pins checked.
     */
    val checkedPins: Int,

    /**
     * Human-readable result.
     */
    val message: String,

    /**
     * Exception type when hashing failed.
     */
    val errorType: String? = null
) {

    /**
     * True when the pin was successfully matched.
     */
    val pinMatched: Boolean
        get() =
            status ==
                    CertificatePinValidationStatus.PIN_MATCH
}

/**
 * Result of validating a certificate chain.
 */
data class CertificateChainPinValidationResult(

    /**
     * Whether any certificate in the chain matched.
     */
    val valid: Boolean,

    /**
     * Overall chain validation state.
     */
    val status:
        CertificatePinValidationStatus,

    /**
     * Index of the matching certificate.
     *
     * 0 normally represents the leaf certificate.
     */
    val matchedCertificateIndex: Int?,

    /**
     * Individual certificate validation results.
     */
    val certificateResults:
        List<CertificatePinValidationResult>,

    /**
     * Human-readable result.
     */
    val message: String
) {

    /**
     * True if any certificate matched.
     */
    val pinMatched: Boolean
        get() =
            valid

    /**
     * Number of certificates checked.
     */
    val certificatesChecked: Int
        get() =
            certificateResults.size
}

/**
 * Certificate pin-set validation result.
 */
data class CertificatePinSetValidationResult(

    /**
     * Whether the entire pin set is valid.
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
     * Invalid pins.
     *
     * Values are masked.
     */
    val invalidPins: List<String>,

    /**
     * Duplicate pins.
     *
     * Values are masked.
     */
    val duplicatePins: List<String>,

    /**
     * Whether at least two valid pins exist.
     */
    val hasBackupPin: Boolean,

    /**
     * Human-readable result.
     */
    val message: String
)

/**
 * Certificate metadata useful for security reporting.
 */
data class CertificatePinCertificateInfo(

    /**
     * Certificate subject.
     */
    val subject: String?,

    /**
     * Certificate issuer.
     */
    val issuer: String?,

    /**
     * Certificate serial number.
     */
    val serialNumber: String,

    /**
     * Certificate validity start timestamp.
     */
    val notBefore: Long,

    /**
     * Certificate validity end timestamp.
     */
    val notAfter: Long,

    /**
     * Public-key algorithm.
     */
    val publicKeyAlgorithm: String,

    /**
     * Certificate signature algorithm.
     */
    val signatureAlgorithm: String,

    /**
     * Calculated public-key pin.
     */
    val pin: String
)

/**
 * Certificate pin validation states.
 */
enum class CertificatePinValidationStatus {

    /**
     * Pin matched.
     */
    PIN_MATCH,

    /**
     * Pin did not match.
     */
    PIN_MISMATCH,

    /**
     * No pins were supplied.
     */
    NO_PINS_CONFIGURED,

    /**
     * Certificate chain was empty.
     */
    EMPTY_CERTIFICATE_CHAIN,

    /**
     * Certificate type was unsupported.
     */
    UNSUPPORTED_CERTIFICATE,

    /**
     * Public-key hash calculation failed.
     */
    HASH_CALCULATION_FAILED
}
