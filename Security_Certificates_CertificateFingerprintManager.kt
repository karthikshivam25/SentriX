package com.sentrix.security.certificates

import android.util.Base64
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap

/**
 * SentriX Certificate Fingerprint Manager
 *
 * Enterprise-grade certificate fingerprint management component.
 *
 * Responsibilities:
 *
 * - Generate certificate fingerprints.
 * - Generate public-key fingerprints.
 * - Generate SHA-256 fingerprints.
 * - Generate SHA-384 fingerprints.
 * - Generate SHA-512 fingerprints.
 * - Generate Base64 fingerprints.
 * - Normalize fingerprint representations.
 * - Compare fingerprints safely.
 * - Compare certificates by cryptographic identity.
 * - Maintain optional certificate fingerprint inventory.
 * - Detect fingerprint algorithm mismatches.
 * - Support certificate pinning and certificate inventory workflows.
 *
 * Fingerprint types:
 *
 * 1. CERTIFICATE
 *    SHA digest of the complete DER-encoded certificate.
 *
 * 2. PUBLIC_KEY
 *    SHA digest of the DER-encoded SubjectPublicKeyInfo.
 *
 * The manager does NOT:
 *
 * - Decide whether a certificate is trusted.
 * - Perform PKIX validation.
 * - Validate certificate expiration.
 * - Modify certificates.
 * - Store private keys.
 * - Bypass Android certificate validation.
 *
 * Trust decisions belong to:
 *
 *      CertificateTrustManager
 *      CertificateValidator
 *      CertificateChainValidator
 *
 * Pin decisions belong to:
 *
 *      CertificatePinManager
 *
 * Architecture:
 *
 *      X509Certificate
 *             │
 *             ▼
 *      CertificateFingerprintManager
 *             │
 *       ┌─────┼──────────────┐
 *       ▼     ▼              ▼
 *    SHA-256 SHA-384      SHA-512
 *       │     │              │
 *       └─────┼──────────────┘
 *             ▼
 *      CertificateFingerprint
 */
class CertificateFingerprintManager {

    /**
     * Optional in-memory fingerprint inventory.
     *
     * The inventory stores only cryptographic identifiers and metadata.
     * It does not store private keys.
     */
    private val fingerprintInventory =
        ConcurrentHashMap<String, CertificateFingerprintRecord>()

    // =========================================================================
    // Certificate Fingerprints
    // =========================================================================

    /**
     * Calculates the SHA-256 fingerprint of the complete certificate.
     *
     * The digest is calculated over the DER encoded X.509 certificate.
     *
     * Example:
     *
     *      AA:BB:CC:DD:...
     */
    fun sha256(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-384 fingerprint of the complete certificate.
     */
    fun sha384(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_384
        )
    }

    /**
     * Calculates SHA-512 fingerprint of the complete certificate.
     */
    fun sha512(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_512
        )
    }

    /**
     * Calculates a certificate fingerprint using a selected algorithm.
     */
    fun calculate(
        certificate: X509Certificate,
        algorithm: FingerprintAlgorithm
    ): String {

        return calculateHex(
            data =
                certificate.encoded,
            algorithm =
                algorithm
        )
    }

    /**
     * Calculates a certificate fingerprint as Base64.
     */
    fun calculateBase64(
        certificate: X509Certificate,
        algorithm: FingerprintAlgorithm =
            FingerprintAlgorithm.SHA_256
    ): String {

        return calculateBase64(
            data =
                certificate.encoded,
            algorithm =
                algorithm
        )
    }

    // =========================================================================
    // Public-Key Fingerprints
    // =========================================================================

    /**
     * Calculates the SHA-256 fingerprint of the certificate's
     * SubjectPublicKeyInfo.
     *
     * This is the preferred identity for public-key pinning.
     */
    fun publicKeySha256(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.publicKey.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_256
        )
    }

    /**
     * Calculates SHA-384 fingerprint of the certificate public key.
     */
    fun publicKeySha384(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.publicKey.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_384
        )
    }

    /**
     * Calculates SHA-512 fingerprint of the certificate public key.
     */
    fun publicKeySha512(
        certificate: X509Certificate
    ): String {

        return calculateHex(
            data =
                certificate.publicKey.encoded,
            algorithm =
                FingerprintAlgorithm.SHA_512
        )
    }

    /**
     * Calculates public-key fingerprint using the selected algorithm.
     */
    fun calculatePublicKey(
        certificate: X509Certificate,
        algorithm: FingerprintAlgorithm
    ): String {

        return calculateHex(
            data =
                certificate.publicKey.encoded,
            algorithm =
                algorithm
        )
    }

    /**
     * Calculates public-key fingerprint as Base64.
     */
    fun calculatePublicKeyBase64(
        certificate: X509Certificate,
        algorithm: FingerprintAlgorithm =
            FingerprintAlgorithm.SHA_256
    ): String {

        return calculateBase64(
            data =
                certificate.publicKey.encoded,
            algorithm =
                algorithm
        )
    }

    // =========================================================================
    // Fingerprint Object
    // =========================================================================

    /**
     * Creates a complete fingerprint object containing the most
     * useful certificate identity information.
     */
    fun createFingerprint(
        certificate: X509Certificate
    ): CertificateFingerprint {

        return CertificateFingerprint(

            certificateSha256 =
                sha256(
                    certificate
                ),

            certificateSha384 =
                sha384(
                    certificate
                ),

            certificateSha512 =
                sha512(
                    certificate
                ),

            certificateSha256Base64 =
                calculateBase64(
                    certificate,
                    FingerprintAlgorithm.SHA_256
                ),

            publicKeySha256 =
                publicKeySha256(
                    certificate
                ),

            publicKeySha384 =
                publicKeySha384(
                    certificate
                ),

            publicKeySha512 =
                publicKeySha512(
                    certificate
                ),

            publicKeySha256Base64 =
                publicKeySha256Base64(
                    certificate
                )
        )
    }

    /**
     * Creates a lightweight fingerprint object.
     */
    fun createCertificateFingerprint(
        certificate: X509Certificate
    ): CertificateFingerprint {

        return createFingerprint(
            certificate
        )
    }

    // =========================================================================
    // Certificate Identity
    // =========================================================================

    /**
     * Determines whether two certificates have exactly the same
     * DER-encoded certificate identity.
     */
    fun isSameCertificate(
        first: X509Certificate,
        second: X509Certificate
    ): Boolean {

        return MessageDigest.isEqual(
            first.encoded,
            second.encoded
        )
    }

    /**
     * Determines whether two certificates have the same SHA-256
     * certificate fingerprint.
     */
    fun hasSameCertificateSha256(
        first: X509Certificate,
        second: X509Certificate
    ): Boolean {

        return constantTimeEquals(
            sha256(first),
            sha256(second)
        )
    }

    /**
     * Determines whether two certificates use the same public key.
     *
     * This ignores the rest of the certificate.
     */
    fun hasSamePublicKey(
        first: X509Certificate,
        second: X509Certificate
    ): Boolean {

        return MessageDigest.isEqual(
            first.publicKey.encoded,
            second.publicKey.encoded
        )
    }

    /**
     * Determines whether two certificates have the same public-key
     * SHA-256 fingerprint.
     */
    fun hasSamePublicKeySha256(
        first: X509Certificate,
        second: X509Certificate
    ): Boolean {

        return constantTimeEquals(
            publicKeySha256(first),
            publicKeySha256(second)
        )
    }

    // =========================================================================
    // Fingerprint Comparison
    // =========================================================================

    /**
     * Compares a certificate against an expected SHA-256 fingerprint.
     */
    fun matchesSha256(
        certificate: X509Certificate,
        expectedFingerprint: String
    ): Boolean {

        return constantTimeEquals(
            sha256(
                certificate
            ),
            expectedFingerprint
        )
    }

    /**
     * Compares a certificate against an expected SHA-384 fingerprint.
     */
    fun matchesSha384(
        certificate: X509Certificate,
        expectedFingerprint: String
    ): Boolean {

        return constantTimeEquals(
            sha384(
                certificate
            ),
            expectedFingerprint
        )
    }

    /**
     * Compares a certificate against an expected SHA-512 fingerprint.
     */
    fun matchesSha512(
        certificate: X509Certificate,
        expectedFingerprint: String
    ): Boolean {

        return constantTimeEquals(
            sha512(
                certificate
            ),
            expectedFingerprint
        )
    }

    /**
     * Compares a certificate public key against a SHA-256 pin.
     */
    fun matchesPublicKeySha256(
        certificate: X509Certificate,
        expectedFingerprint: String
    ): Boolean {

        return constantTimeEquals(
            publicKeySha256(
                certificate
            ),
            expectedFingerprint
        )
    }

    /**
     * Compares a certificate against any fingerprint in a collection.
     */
    fun matchesAny(
        certificate: X509Certificate,
        fingerprints: Collection<String>,
        algorithm: FingerprintAlgorithm =
            FingerprintAlgorithm.SHA_256
    ): Boolean {

        val actual =
            calculate(
                certificate,
                algorithm
            )

        return fingerprints.any {
            constantTimeEquals(
                actual,
                it
            )
        }
    }

    /**
     * Compares a certificate public key against any configured
     * public-key fingerprint.
     */
    fun matchesAnyPublicKey(
        certificate: X509Certificate,
        fingerprints: Collection<String>,
        algorithm: FingerprintAlgorithm =
            FingerprintAlgorithm.SHA_256
    ): Boolean {

        val actual =
            calculatePublicKey(
                certificate,
                algorithm
            )

        return fingerprints.any {
            constantTimeEquals(
                actual,
                it
            )
        }
    }

    // =========================================================================
    // Constant-Time Comparison
    // =========================================================================

    /**
     * Performs constant-time comparison of fingerprint strings.
     *
     * Fingerprints are first normalized into binary digest values.
     */
    fun constantTimeEquals(
        first: String,
        second: String
    ): Boolean {

        val firstBytes =
            decodeFingerprint(
                first
            )

        val secondBytes =
            decodeFingerprint(
                second
            )

        if (
            firstBytes == null ||
            secondBytes == null
        ) {

            return false
        }

        return MessageDigest.isEqual(
            firstBytes,
            secondBytes
        )
    }

    /**
     * Performs constant-time comparison of byte arrays.
     */
    fun constantTimeEquals(
        first: ByteArray,
        second: ByteArray
    ): Boolean {

        return MessageDigest.isEqual(
            first,
            second
        )
    }

    // =========================================================================
    // Normalization
    // =========================================================================

    /**
     * Normalizes a fingerprint into uppercase compact hexadecimal.
     *
     * Supported hexadecimal formats:
     *
     *      AA:BB:CC
     *      AA-BB-CC
     *      AABBCC
     *      aa bb cc
     */
    fun normalize(
        fingerprint: String
    ): String {

        val compact =
            fingerprint
                .trim()
                .replace(
                    ":",
                    ""
                )
                .replace(
                    "-",
                    ""
                )
                .replace(
                    " ",
                    ""
                )
                .uppercase()

        return compact
    }

    /**
     * Converts a normalized hexadecimal fingerprint into
     * colon-separated hexadecimal.
     */
    fun toColonSeparated(
        fingerprint: String
    ): String {

        val normalized =
            normalize(
                fingerprint
            )

        if (
            normalized.length % 2 != 0
        ) {

            throw IllegalArgumentException(
                "Fingerprint contains an invalid number of hexadecimal characters."
            )
        }

        return normalized
            .chunked(
                2
            )
            .joinToString(
                ":"
            )
    }

    /**
     * Converts a fingerprint into lowercase hexadecimal.
     */
    fun toLowercaseHex(
        fingerprint: String
    ): String {

        return normalize(
            fingerprint
        ).lowercase()
    }

    // =========================================================================
    // Fingerprint Decoding
    // =========================================================================

    /**
     * Decodes either hexadecimal or Base64 fingerprint representation.
     */
    fun decodeFingerprint(
        fingerprint: String
    ): ByteArray? {

        val normalized =
            fingerprint.trim()

        if (
            normalized.isBlank()
        ) {

            return null
        }

        val compactHex =
            normalize(
                normalized
            )

        /**
         * Hex fingerprint.
         */
        if (
            compactHex.isNotEmpty() &&
            compactHex.length % 2 == 0 &&
            compactHex.matches(
                Regex(
                    "[0-9A-F]+"
                )
            )
        ) {

            return try {

                ByteArray(
                    compactHex.length / 2
                ) { index ->

                    compactHex
                        .substring(
                            index * 2,
                            index * 2 + 2
                        )
                        .toInt(
                            16
                        )
                        .toByte()
                }

            } catch (
                _: Exception
            ) {

                null
            }
        }

        /**
         * Base64 fingerprint.
         */
        return try {

            Base64.decode(
                normalized,
                Base64.DEFAULT
            )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Converts hexadecimal fingerprint to Base64.
     */
    fun hexToBase64(
        fingerprint: String
    ): String {

        val bytes =
            decodeFingerprint(
                fingerprint
            )
                ?: throw IllegalArgumentException(
                    "Invalid hexadecimal fingerprint."
                )

        return Base64.encodeToString(
            bytes,
            Base64.NO_WRAP
        )
    }

    /**
     * Converts Base64 fingerprint to uppercase hexadecimal.
     */
    fun base64ToHex(
        fingerprint: String
    ): String {

        val bytes =
            try {

                Base64.decode(
                    fingerprint,
                    Base64.DEFAULT
                )

            } catch (
                exception: Exception
            ) {

                throw IllegalArgumentException(
                    "Invalid Base64 fingerprint.",
                    exception
                )
            }

        return bytes.joinToString(":") {
            "%02X".format(
                it.toInt() and 0xFF
            )
        }
    }

    // =========================================================================
    // Fingerprint Validation
    // =========================================================================

    /**
     * Validates a fingerprint representation.
     */
    fun validateFingerprint(
        fingerprint: String,
        algorithm: FingerprintAlgorithm
    ): FingerprintValidationResult {

        if (
            fingerprint.isBlank()
        ) {

            return FingerprintValidationResult.Invalid(
                "Fingerprint must not be blank."
            )
        }

        val bytes =
            decodeFingerprint(
                fingerprint
            )
                ?: return FingerprintValidationResult.Invalid(
                    "Fingerprint is not valid hexadecimal or Base64."
                )

        if (
            bytes.size !=
            algorithm.digestSizeBytes
        ) {

            return FingerprintValidationResult.Invalid(
                "Fingerprint length does not match ${algorithm.displayName}."
            )
        }

        return FingerprintValidationResult.Valid
    }

    /**
     * Determines whether a fingerprint has the expected SHA-256 length.
     */
    fun isValidSha256(
        fingerprint: String
    ): Boolean {

        return validateFingerprint(
            fingerprint,
            FingerprintAlgorithm.SHA_256
        ) is FingerprintValidationResult.Valid
    }

    /**
     * Determines whether a fingerprint has the expected SHA-384 length.
     */
    fun isValidSha384(
        fingerprint: String
    ): Boolean {

        return validateFingerprint(
            fingerprint,
            FingerprintAlgorithm.SHA_384
        ) is FingerprintValidationResult.Valid
    }

    /**
     * Determines whether a fingerprint has the expected SHA-512 length.
     */
    fun isValidSha512(
        fingerprint: String
    ): Boolean {

        return validateFingerprint(
            fingerprint,
            FingerprintAlgorithm.SHA_512
        ) is FingerprintValidationResult.Valid
    }

    // =========================================================================
    // Fingerprint Inventory
    // =========================================================================

    /**
     * Registers a certificate in the in-memory fingerprint inventory.
     *
     * The certificate itself is not stored.
     */
    fun register(
        certificate: X509Certificate,
        label: String? = null
    ): CertificateFingerprintRecord {

        val fingerprint =
            createFingerprint(
                certificate
            )

        val record =
            CertificateFingerprintRecord(

                certificateSha256 =
                    fingerprint
                        .certificateSha256,

                publicKeySha256 =
                    fingerprint
                        .publicKeySha256,

                subject =
                    certificate
                        .subjectX500Principal
                        .name,

                issuer =
                    certificate
                        .issuerX500Principal
                        .name,

                serialNumber =
                    certificate
                        .serialNumber
                        .toString(
                            16
                        ),

                label =
                    label,

                registeredAtMillis =
                    System.currentTimeMillis()
            )

        fingerprintInventory[
            fingerprint.certificateSha256
        ] =
            record

        return record
    }

    /**
     * Removes a certificate fingerprint from the inventory.
     */
    fun unregister(
        certificate: X509Certificate
    ): Boolean {

        val fingerprint =
            sha256(
                certificate
            )

        return fingerprintInventory.remove(
            normalize(
                fingerprint
            )
        ) != null
    }

    /**
     * Removes an inventory record using its SHA-256 fingerprint.
     */
    fun unregister(
        certificateSha256: String
    ): Boolean {

        return fingerprintInventory.remove(
            normalize(
                certificateSha256
            )
        ) != null
    }

    /**
     * Finds an inventory record by certificate SHA-256.
     */
    fun find(
        certificateSha256: String
    ): CertificateFingerprintRecord? {

        return fingerprintInventory[
            normalize(
                certificateSha256
            )
        ]
    }

    /**
     * Determines whether a certificate exists in the inventory.
     */
    fun contains(
        certificate: X509Certificate
    ): Boolean {

        return fingerprintInventory.containsKey(
            normalize(
                sha256(
                    certificate
                )
            )
        )
    }

    /**
     * Returns all fingerprint inventory records.
     */
    fun getInventory():
            List<CertificateFingerprintRecord> {

        return fingerprintInventory
            .values
            .toList()
    }

    /**
     * Clears the fingerprint inventory.
     */
    fun clearInventory() {

        fingerprintInventory.clear()
    }

    /**
     * Returns the current inventory size.
     */
    fun getInventorySize(): Int {

        return fingerprintInventory.size
    }

    // =========================================================================
    // Fingerprint Search
    // =========================================================================

    /**
     * Searches the inventory by certificate fingerprint.
     */
    fun findByCertificateSha256(
        fingerprint: String
    ): CertificateFingerprintRecord? {

        return find(
            fingerprint
        )
    }

    /**
     * Searches the inventory by public-key fingerprint.
     */
    fun findByPublicKeySha256(
        fingerprint: String
    ): List<CertificateFingerprintRecord> {

        val normalized =
            normalize(
                fingerprint
            )

        return fingerprintInventory
            .values
            .filter {
                normalize(
                    it.publicKeySha256
                ) == normalized
            }
    }

    // =========================================================================
    // Certificate Fingerprint Comparison
    // =========================================================================

    /**
     * Compares a certificate against a CertificateFingerprint object.
     */
    fun matches(
        certificate: X509Certificate,
        fingerprint: CertificateFingerprint
    ): Boolean {

        return constantTimeEquals(
            sha256(
                certificate
            ),
            fingerprint.certificateSha256
        )
    }

    /**
     * Compares a certificate public key against a
     * CertificateFingerprint object.
     */
    fun matchesPublicKey(
        certificate: X509Certificate,
        fingerprint: CertificateFingerprint
    ): Boolean {

        return constantTimeEquals(
            publicKeySha256(
                certificate
            ),
            fingerprint.publicKeySha256
        )
    }

    /**
     * Returns the identity relationship between two certificates.
     */
    fun compare(
        first: X509Certificate,
        second: X509Certificate
    ): CertificateIdentityComparison {

        val sameCertificate =
            isSameCertificate(
                first,
                second
            )

        if (
            sameCertificate
        ) {

            return CertificateIdentityComparison
                .SameCertificate
        }

        val samePublicKey =
            hasSamePublicKey(
                first,
                second
            )

        return if (
            samePublicKey
        ) {

            CertificateIdentityComparison
                .SamePublicKeyDifferentCertificate

        } else {

            CertificateIdentityComparison
                .DifferentCertificateAndPublicKey
        }
    }

    // =========================================================================
    // Internal Digest Operations
    // =========================================================================

    /**
     * Calculates a digest and returns colon-separated hexadecimal.
     */
    private fun calculateHex(
        data: ByteArray,
        algorithm: FingerprintAlgorithm
    ): String {

        require(
            data.isNotEmpty()
        ) {
            "Fingerprint input must not be empty."
        }

        val digest =
            MessageDigest.getInstance(
                algorithm.jcaName
            )

        return digest
            .digest(
                data
            )
            .joinToString(":") {
                "%02X".format(
                    it.toInt() and 0xFF
                )
            }
    }

    /**
     * Calculates a digest and returns Base64.
     */
    private fun calculateBase64(
        data: ByteArray,
        algorithm: FingerprintAlgorithm
    ): String {

        require(
            data.isNotEmpty()
        ) {
            "Fingerprint input must not be empty."
        }

        val digest =
            MessageDigest.getInstance(
                algorithm.jcaName
            )

        return Base64.encodeToString(
            digest.digest(
                data
            ),
            Base64.NO_WRAP
        )
    }
}

/**
 * Supported fingerprint algorithms.
 */
enum class FingerprintAlgorithm(

    /**
     * JCA MessageDigest algorithm name.
     */
    val jcaName: String,

    /**
     * Human-readable algorithm name.
     */
    val displayName: String,

    /**
     * Digest size in bytes.
     */
    val digestSizeBytes: Int
) {

    SHA_256(
        jcaName = "SHA-256",
        displayName = "SHA-256",
        digestSizeBytes = 32
    ),

    SHA_384(
        jcaName = "SHA-384",
        displayName = "SHA-384",
        digestSizeBytes = 48
    ),

    SHA_512(
        jcaName = "SHA-512",
        displayName = "SHA-512",
        digestSizeBytes = 64
    )
}

/**
 * Complete certificate fingerprint information.
 *
 * This object contains certificate identity information only.
 */
data class CertificateFingerprint(

    /**
     * SHA-256 of the complete DER certificate.
     */
    val certificateSha256: String,

    /**
     * SHA-384 of the complete DER certificate.
     */
    val certificateSha384: String,

    /**
     * SHA-512 of the complete DER certificate.
     */
    val certificateSha512: String,

    /**
     * Base64 SHA-256 of the complete DER certificate.
     */
    val certificateSha256Base64: String,

    /**
     * SHA-256 of the SubjectPublicKeyInfo.
     */
    val publicKeySha256: String,

    /**
     * SHA-384 of the SubjectPublicKeyInfo.
     */
    val publicKeySha384: String,

    /**
     * SHA-512 of the SubjectPublicKeyInfo.
     */
    val publicKeySha512: String,

    /**
     * Base64 SHA-256 of the SubjectPublicKeyInfo.
     */
    val publicKeySha256Base64: String
)

/**
 * Fingerprint inventory record.
 *
 * The actual X509Certificate object is deliberately not retained.
 */
data class CertificateFingerprintRecord(

    val certificateSha256: String,

    val publicKeySha256: String,

    val subject: String,

    val issuer: String,

    val serialNumber: String,

    val label: String?,

    val registeredAtMillis: Long
)

/**
 * Result of fingerprint validation.
 */
sealed class FingerprintValidationResult {

    /**
     * Fingerprint is valid for the requested algorithm.
     */
    data object Valid :
        FingerprintValidationResult()

    /**
     * Fingerprint is malformed.
     */
    data class Invalid(
        val reason: String
    ) : FingerprintValidationResult()
}

/**
 * Represents the cryptographic identity relationship between
 * two certificates.
 */
enum class CertificateIdentityComparison {

    /**
     * Complete DER certificates are identical.
     */
    SameCertificate,

    /**
     * Certificates differ but contain the same public key.
     */
    SamePublicKeyDifferentCertificate,

    /**
     * Certificates and public keys are different.
     */
    DifferentCertificateAndPublicKey
}
