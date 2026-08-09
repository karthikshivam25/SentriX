package com.sentrix.security.certificates

import android.content.Context
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.X509Certificate
import java.util.Date

/**
 * SentriX Certificate Manager
 *
 * Central certificate lifecycle and inspection manager for the SentriX
 * security subsystem.
 *
 * Responsibilities:
 *
 * - Parse X.509 certificates.
 * - Validate certificate validity periods.
 * - Calculate certificate fingerprints.
 * - Inspect certificate metadata.
 * - Detect expired certificates.
 * - Detect certificates that are not yet valid.
 * - Inspect certificate chains.
 * - Compare certificates.
 * - Validate certificate chains using the platform trust store.
 * - Identify certificate key/signature information.
 * - Provide security-oriented certificate reports.
 *
 * This class DOES NOT:
 *
 * - Replace Android's TLS implementation.
 * - Disable certificate validation.
 * - Accept invalid certificates.
 * - Implement custom TLS sockets.
 * - Perform SSL pinning enforcement.
 * - Store private keys.
 * - Extract private key material.
 *
 * Certificate pinning should be implemented separately in:
 *
 *      security/
 *          certificates/
 *          sslpinning/
 *
 * Android's platform trust infrastructure remains authoritative for
 * normal TLS certificate-chain validation.
 *
 * Architecture:
 *
 *      SentriX Security Layer
 *               │
 *               ▼
 *       CertificateManager
 *               │
 *        ┌──────┼──────┐
 *        ▼      ▼      ▼
 *    Parser  Validator Fingerprint
 *        │      │      │
 *        └──────┼──────┘
 *               ▼
 *       CertificateReport
 */
class CertificateManager(
    private val context: Context
) {

    /**
     * Application context is retained to avoid accidentally keeping
     * an Activity or other short-lived Context alive.
     */
    private val applicationContext =
        context.applicationContext

    // =========================================================================
    // Certificate Parsing
    // =========================================================================

    /**
     * Parses a DER-encoded X.509 certificate.
     *
     * @param certificateBytes DER-encoded certificate bytes.
     *
     * @return Parsed X509Certificate.
     *
     * @throws CertificateException if the certificate cannot be parsed.
     */
    fun parseCertificate(
        certificateBytes: ByteArray
    ): X509Certificate {

        require(
            certificateBytes.isNotEmpty()
        ) {
            "Certificate data must not be empty."
        }

        val certificateFactory =
            CertificateFactory.getInstance(
                CertificateConstants.X509_TYPE
            )

        return certificateFactory
            .generateCertificate(
                ByteArrayInputStream(
                    certificateBytes
                )
            ) as X509Certificate
    }

    /**
     * Parses a certificate from a PEM string.
     *
     * Both the PEM headers and Base64 content are supported.
     */
    fun parsePemCertificate(
        pemCertificate: String
    ): X509Certificate {

        require(
            pemCertificate.isNotBlank()
        ) {
            "PEM certificate must not be blank."
        }

        val cleanedCertificate =
            pemCertificate
                .replace(
                    CertificateConstants.PEM_BEGIN_CERTIFICATE,
                    ""
                )
                .replace(
                    CertificateConstants.PEM_END_CERTIFICATE,
                    ""
                )
                .replace(
                    "\\s".toRegex(),
                    ""
                )

        val certificateBytes =
            try {

                android.util.Base64.decode(
                    cleanedCertificate,
                    android.util.Base64.DEFAULT
                )

            } catch (exception: IllegalArgumentException) {

                throw IllegalArgumentException(
                    "Invalid PEM certificate encoding.",
                    exception
                )
            }

        return parseCertificate(
            certificateBytes
        )
    }

    // =========================================================================
    // Certificate Metadata
    // =========================================================================

    /**
     * Returns the certificate subject distinguished name.
     */
    fun getSubject(
        certificate: X509Certificate
    ): String {

        return certificate.subjectX500Principal.name
    }

    /**
     * Returns the certificate issuer distinguished name.
     */
    fun getIssuer(
        certificate: X509Certificate
    ): String {

        return certificate.issuerX500Principal.name
    }

    /**
     * Returns the certificate serial number.
     */
    fun getSerialNumber(
        certificate: X509Certificate
    ): String {

        return certificate.serialNumber.toString(
            CertificateConstants.SERIAL_NUMBER_RADIX
        )
    }

    /**
     * Returns the certificate version.
     */
    fun getVersion(
        certificate: X509Certificate
    ): Int {

        return certificate.version
    }

    /**
     * Returns the certificate start/activation date.
     */
    fun getValidFrom(
        certificate: X509Certificate
    ): Date {

        return certificate.notBefore
    }

    /**
     * Returns the certificate expiration date.
     */
    fun getValidUntil(
        certificate: X509Certificate
    ): Date {

        return certificate.notAfter
    }

    /**
     * Returns the public-key algorithm.
     */
    fun getPublicKeyAlgorithm(
        certificate: X509Certificate
    ): String {

        return certificate.publicKey.algorithm
    }

    /**
     * Returns the public-key format.
     */
    fun getPublicKeyFormat(
        certificate: X509Certificate
    ): String {

        return certificate.publicKey.format
    }

    /**
     * Returns the certificate signature algorithm.
     */
    fun getSignatureAlgorithm(
        certificate: X509Certificate
    ): String {

        return certificate.sigAlgName
    }

    /**
     * Returns the certificate signature algorithm OID.
     */
    fun getSignatureAlgorithmOid(
        certificate: X509Certificate
    ): String {

        return certificate.sigAlgOID
    }

    // =========================================================================
    // Validity
    // =========================================================================

    /**
     * Checks whether the certificate is currently within its validity
     * period.
     */
    fun isCurrentlyValid(
        certificate: X509Certificate
    ): Boolean {

        return try {

            certificate.checkValidity()

            true

        } catch (
            _: CertificateExpiredException
        ) {

            false

        } catch (
            _: CertificateNotYetValidException
        ) {

            false
        }
    }

    /**
     * Checks whether the certificate has expired.
     */
    fun isExpired(
        certificate: X509Certificate
    ): Boolean {

        return Date().after(
            certificate.notAfter
        )
    }

    /**
     * Checks whether the certificate is not yet valid.
     */
    fun isNotYetValid(
        certificate: X509Certificate
    ): Boolean {

        return Date().before(
            certificate.notBefore
        )
    }

    /**
     * Returns the number of milliseconds remaining before expiration.
     *
     * A negative value indicates that the certificate has already expired.
     */
    fun getTimeUntilExpiration(
        certificate: X509Certificate,
        now: Date = Date()
    ): Long {

        return certificate.notAfter.time -
                now.time
    }

    /**
     * Returns the number of days remaining before certificate expiration.
     */
    fun getDaysUntilExpiration(
        certificate: X509Certificate,
        now: Date = Date()
    ): Long {

        return getTimeUntilExpiration(
            certificate = certificate,
            now = now
        ) /
                CertificateConstants.MILLIS_PER_DAY
    }

    /**
     * Determines whether the certificate is approaching expiration.
     */
    fun isExpiringSoon(
        certificate: X509Certificate,
        thresholdDays: Long =
            CertificateConstants.DEFAULT_EXPIRY_WARNING_DAYS
    ): Boolean {

        if (isExpired(certificate)) {
            return false
        }

        val daysRemaining =
            getDaysUntilExpiration(
                certificate
            )

        return daysRemaining in
                0..thresholdDays
    }

    // =========================================================================
    // Fingerprints
    // =========================================================================

    /**
     * Generates a SHA-256 fingerprint of the complete DER certificate.
     *
     * The returned value is formatted as uppercase hexadecimal bytes
     * separated by colons.
     *
     * Example:
     *
     *      AA:BB:CC:DD:...
     */
    fun getSha256Fingerprint(
        certificate: Certificate
    ): String {

        return calculateFingerprint(
            certificate = certificate,
            algorithm =
                CertificateConstants.HASH_SHA_256
        )
    }

    /**
     * Generates a SHA-1 fingerprint.
     *
     * SHA-1 should generally only be used for compatibility or
     * identification purposes, not as a modern security primitive.
     */
    fun getSha1Fingerprint(
        certificate: Certificate
    ): String {

        return calculateFingerprint(
            certificate = certificate,
            algorithm =
                CertificateConstants.HASH_SHA_1
        )
    }

    /**
     * Generates a fingerprint using the requested digest algorithm.
     */
    fun calculateFingerprint(
        certificate: Certificate,
        algorithm: String
    ): String {

        val digest =
            MessageDigest.getInstance(
                algorithm
            )

        val encodedCertificate =
            certificate.encoded

        val fingerprint =
            digest.digest(
                encodedCertificate
            )

        return fingerprint.joinToString(
            separator =
                CertificateConstants.FINGERPRINT_SEPARATOR
        ) { byte ->

            "%02X".format(
                byte.toInt() and 0xFF
            )
        }
    }

    /**
     * Generates a SHA-256 fingerprint directly from certificate bytes.
     */
    fun getSha256Fingerprint(
        certificateBytes: ByteArray
    ): String {

        val certificate =
            parseCertificate(
                certificateBytes
            )

        return getSha256Fingerprint(
            certificate
        )
    }

    /**
     * Compares a certificate against a SHA-256 fingerprint.
     */
    fun matchesSha256Fingerprint(
        certificate: Certificate,
        expectedFingerprint: String
    ): Boolean {

        val actualFingerprint =
            getSha256Fingerprint(
                certificate
            )

        return normalizeFingerprint(
            actualFingerprint
        ) ==
                normalizeFingerprint(
                    expectedFingerprint
                )
    }

    /**
     * Normalizes a fingerprint before comparison.
     */
    private fun normalizeFingerprint(
        fingerprint: String
    ): String {

        return fingerprint
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "")
            .uppercase()
    }

    // =========================================================================
    // Certificate Type
    // =========================================================================

    /**
     * Determines whether the certificate is a CA certificate.
     */
    fun isCertificateAuthority(
        certificate: X509Certificate
    ): Boolean {

        return certificate.basicConstraints >= 0
    }

    /**
     * Determines whether the certificate is an end-entity certificate.
     */
    fun isEndEntityCertificate(
        certificate: X509Certificate
    ): Boolean {

        return certificate.basicConstraints < 0
    }

    /**
     * Returns the certificate's basic constraints value.
     */
    fun getBasicConstraints(
        certificate: X509Certificate
    ): Int {

        return certificate.basicConstraints
    }

    // =========================================================================
    // Key Usage
    // =========================================================================

    /**
     * Returns the certificate's key-usage flags.
     *
     * A null value means the extension is not present.
     */
    fun getKeyUsage(
        certificate: X509Certificate
    ): BooleanArray? {

        return certificate.keyUsage
    }

    /**
     * Determines whether the certificate has digital-signature usage.
     */
    fun allowsDigitalSignature(
        certificate: X509Certificate
    ): Boolean {

        val keyUsage =
            certificate.keyUsage
                ?: return false

        return keyUsage.size >
                CertificateConstants.KEY_USAGE_DIGITAL_SIGNATURE &&
                keyUsage[
                    CertificateConstants.KEY_USAGE_DIGITAL_SIGNATURE
                ]
    }

    /**
     * Determines whether the certificate may be used for key
     * encipherment.
     */
    fun allowsKeyEncipherment(
        certificate: X509Certificate
    ): Boolean {

        val keyUsage =
            certificate.keyUsage
                ?: return false

        return keyUsage.size >
                CertificateConstants.KEY_USAGE_KEY_ENCIPHERMENT &&
                keyUsage[
                    CertificateConstants.KEY_USAGE_KEY_ENCIPHERMENT
                ]
    }

    // =========================================================================
    // Extended Key Usage
    // =========================================================================

    /**
     * Returns extended key usage OIDs.
     */
    fun getExtendedKeyUsage(
        certificate: X509Certificate
    ): List<String> {

        return certificate.extendedKeyUsage
            ?: emptyList()
    }

    /**
     * Determines whether the certificate contains the TLS
     * server-authentication extended key usage.
     */
    fun allowsServerAuthentication(
        certificate: X509Certificate
    ): Boolean {

        val usage =
            certificate.extendedKeyUsage
                ?: return true

        return CertificateConstants
            .TLS_SERVER_AUTH_OID in usage
    }

    /**
     * Determines whether the certificate contains TLS
     * client-authentication extended key usage.
     */
    fun allowsClientAuthentication(
        certificate: X509Certificate
    ): Boolean {

        val usage =
            certificate.extendedKeyUsage
                ?: return true

        return CertificateConstants
            .TLS_CLIENT_AUTH_OID in usage
    }

    // =========================================================================
    // Subject Alternative Names
    // =========================================================================

    /**
     * Returns the certificate's Subject Alternative Name entries.
     *
     * The raw GeneralName structure is returned because Android's
     * certificate APIs represent SAN values using type/value pairs.
     */
    fun getSubjectAlternativeNames(
        certificate: X509Certificate
    ): Collection<List<*>> {

        return certificate.subjectAlternativeNames
            ?: emptyList()
    }

    /**
     * Returns DNS names from the certificate SAN extension.
     */
    fun getDnsNames(
        certificate: X509Certificate
    ): List<String> {

        return extractSubjectAlternativeNames(
            certificate = certificate,
            type = CertificateConstants.SAN_DNS_NAME
        )
    }

    /**
     * Returns IP addresses from the certificate SAN extension.
     */
    fun getIpAddresses(
        certificate: X509Certificate
    ): List<String> {

        return extractSubjectAlternativeNames(
            certificate = certificate,
            type = CertificateConstants.SAN_IP_ADDRESS
        )
    }

    /**
     * Extracts SAN values for a specific GeneralName type.
     */
    private fun extractSubjectAlternativeNames(
        certificate: X509Certificate,
        type: Int
    ): List<String> {

        val names =
            certificate.subjectAlternativeNames
                ?: return emptyList()

        return names
            .filter {
                it.size >= 2 &&
                        it[0] == type
            }
            .mapNotNull {
                it[1]?.toString()
            }
    }

    // =========================================================================
    // Certificate Comparison
    // =========================================================================

    /**
     * Compares two certificates using their encoded DER representation.
     */
    fun areEqual(
        first: Certificate,
        second: Certificate
    ): Boolean {

        return try {

            first.encoded.contentEquals(
                second.encoded
            )

        } catch (
            _: Exception
        ) {

            false
        }
    }

    /**
     * Determines whether two certificates have the same SHA-256
     * fingerprint.
     */
    fun haveSameSha256Fingerprint(
        first: Certificate,
        second: Certificate
    ): Boolean {

        return getSha256Fingerprint(
            first
        ) ==
                getSha256Fingerprint(
                    second
                )
    }

    // =========================================================================
    // Certificate Signature Verification
    // =========================================================================

    /**
     * Verifies that a certificate was correctly signed by the supplied
     * issuer certificate.
     *
     * This verifies the cryptographic signature relationship only.
     *
     * It does NOT perform complete PKIX path validation.
     */
    fun verifySignedBy(
        certificate: X509Certificate,
        issuer: X509Certificate
    ): Boolean {

        return try {

            certificate.verify(
                issuer.publicKey
            )

            true

        } catch (
            _: Exception
        ) {

            false
        }
    }

    // =========================================================================
    // Chain Inspection
    // =========================================================================

    /**
     * Returns whether a certificate chain is ordered from leaf
     * certificate toward its issuer.
     */
    fun isChainOrdered(
        certificateChain: List<X509Certificate>
    ): Boolean {

        if (
            certificateChain.isEmpty()
        ) {

            return false
        }

        if (
            certificateChain.size == 1
        ) {

            return true
        }

        for (
            index in 0 until
                    certificateChain.size - 1
        ) {

            val certificate =
                certificateChain[index]

            val issuer =
                certificateChain[index + 1]

            if (
                !verifySignedBy(
                    certificate = certificate,
                    issuer = issuer
                )
            ) {

                return false
            }
        }

        return true
    }

    /**
     * Checks validity periods for every certificate in a chain.
     */
    fun isChainCurrentlyValid(
        certificateChain: List<X509Certificate>
    ): Boolean {

        if (
            certificateChain.isEmpty()
        ) {

            return false
        }

        return certificateChain.all {
            isCurrentlyValid(it)
        }
    }

    /**
     * Returns the number of certificates in the chain.
     */
    fun getChainLength(
        certificateChain: List<X509Certificate>
    ): Int {

        return certificateChain.size
    }

    /**
     * Returns the root-most certificate from a conventional
     * leaf-to-root certificate chain.
     */
    fun getRootCertificate(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.lastOrNull()
    }

    /**
     * Returns the leaf/end-entity certificate from a conventional
     * leaf-to-root certificate chain.
     */
    fun getLeafCertificate(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.firstOrNull()
    }

    // =========================================================================
    // Platform Trust Store
    // =========================================================================

    /**
     * Attempts to obtain the Android system trust store.
     *
     * The returned KeyStore is intended for inspection and trust-path
     * operations. Applications should not modify the system trust store.
     */
    fun getSystemTrustStore(): KeyStore {

        val trustStore =
            KeyStore.getInstance(
                CertificateConstants.ANDROID_TRUST_STORE
            )

        trustStore.load(
            null
        )

        return trustStore
    }

    /**
     * Checks whether a certificate exists in the Android system
     * trust store by SHA-256 fingerprint.
     */
    fun isTrustedBySystemStore(
        certificate: X509Certificate
    ): Boolean {

        val targetFingerprint =
            getSha256Fingerprint(
                certificate
            )

        val trustStore =
            try {

                getSystemTrustStore()

            } catch (
                _: Exception
            ) {

                return false
            }

        val aliases =
            trustStore.aliases()

        while (
            aliases.hasMoreElements()
        ) {

            val alias =
                aliases.nextElement()

            val trustedCertificate =
                trustStore
                    .getCertificate(
                        alias
                    ) as? X509Certificate
                    ?: continue

            val fingerprint =
                getSha256Fingerprint(
                    trustedCertificate
                )

            if (
                fingerprint ==
                targetFingerprint
            ) {

                return true
            }
        }

        return false
    }

    // =========================================================================
    // Certificate Report
    // =========================================================================

    /**
     * Creates a comprehensive security-oriented certificate report.
     */
    fun createCertificateReport(
        certificate: X509Certificate
    ): CertificateReport {

        val now =
            Date()

        val valid =
            isCurrentlyValid(
                certificate
            )

        val expired =
            isExpired(
                certificate
            )

        val notYetValid =
            isNotYetValid(
                certificate
            )

        val daysRemaining =
            getDaysUntilExpiration(
                certificate,
                now
            )

        return CertificateReport(
            subject =
                getSubject(
                    certificate
                ),

            issuer =
                getIssuer(
                    certificate
                ),

            serialNumber =
                getSerialNumber(
                    certificate
                ),

            version =
                getVersion(
                    certificate
                ),

            validFrom =
                getValidFrom(
                    certificate
                ),

            validUntil =
                getValidUntil(
                    certificate
                ),

            currentlyValid =
                valid,

            expired =
                expired,

            notYetValid =
                notYetValid,

            expiringSoon =
                isExpiringSoon(
                    certificate
                ),

            daysUntilExpiration =
                daysRemaining,

            sha256Fingerprint =
                getSha256Fingerprint(
                    certificate
                ),

            sha1Fingerprint =
                getSha1Fingerprint(
                    certificate
                ),

            publicKeyAlgorithm =
                getPublicKeyAlgorithm(
                    certificate
                ),

            publicKeyFormat =
                getPublicKeyFormat(
                    certificate
                ),

            signatureAlgorithm =
                getSignatureAlgorithm(
                    certificate
                ),

            signatureAlgorithmOid =
                getSignatureAlgorithmOid(
                    certificate
                ),

            certificateAuthority =
                isCertificateAuthority(
                    certificate
                ),

            dnsNames =
                getDnsNames(
                    certificate
                ),

            ipAddresses =
                getIpAddresses(
                    certificate
                ),

            allowsServerAuthentication =
                allowsServerAuthentication(
                    certificate
                ),

            allowsClientAuthentication =
                allowsClientAuthentication(
                    certificate
                )
        )
    }

    // =========================================================================
    // Security Assessment
    // =========================================================================

    /**
     * Performs a basic certificate security assessment.
     *
     * This is an inspection assessment, not a replacement for full
     * platform PKIX validation.
     */
    fun assessSecurity(
        certificate: X509Certificate
    ): CertificateSecurityAssessment {

        val issues =
            mutableListOf<CertificateSecurityIssue>()

        if (
            isExpired(
                certificate
            )
        ) {

            issues.add(
                CertificateSecurityIssue.EXPIRED
            )
        }

        if (
            isNotYetValid(
                certificate
            )
        ) {

            issues.add(
                CertificateSecurityIssue.NOT_YET_VALID
            )
        }

        if (
            isExpiringSoon(
                certificate
            )
        ) {

            issues.add(
                CertificateSecurityIssue.EXPIRING_SOON
            )
        }

        if (
            getPublicKeyAlgorithm(
                certificate
            ).equals(
                CertificateConstants.LEGACY_RSA_ALGORITHM,
                ignoreCase = true
            )
        ) {

            /**
             * This is an informational assessment rather than a blanket
             * rejection. Actual key-strength validation belongs in the
             * certificate policy layer.
             */
            issues.add(
                CertificateSecurityIssue.RSA_KEY_REVIEW_REQUIRED
            )
        }

        return CertificateSecurityAssessment(
            secure =
                issues.none {
                    it.isBlocking
                },

            issues =
                issues.toList()
        )
    }
}

/**
 * Detailed certificate metadata and security report.
 */
data class CertificateReport(
    val subject: String,
    val issuer: String,
    val serialNumber: String,
    val version: Int,

    val validFrom: Date,
    val validUntil: Date,

    val currentlyValid: Boolean,
    val expired: Boolean,
    val notYetValid: Boolean,
    val expiringSoon: Boolean,

    val daysUntilExpiration: Long,

    val sha256Fingerprint: String,
    val sha1Fingerprint: String,

    val publicKeyAlgorithm: String,
    val publicKeyFormat: String,

    val signatureAlgorithm: String,
    val signatureAlgorithmOid: String,

    val certificateAuthority: Boolean,

    val dnsNames: List<String>,
    val ipAddresses: List<String>,

    val allowsServerAuthentication: Boolean,
    val allowsClientAuthentication: Boolean
)

/**
 * Result of a basic certificate security assessment.
 */
data class CertificateSecurityAssessment(
    val secure: Boolean,
    val issues: List<CertificateSecurityIssue>
)

/**
 * Certificate security issues identified by CertificateManager.
 */
enum class CertificateSecurityIssue(
    val isBlocking: Boolean
) {

    /**
     * Certificate has expired.
     */
    EXPIRED(
        isBlocking = true
    ),

    /**
     * Certificate is not yet valid.
     */
    NOT_YET_VALID(
        isBlocking = true
    ),

    /**
     * Certificate is approaching expiration.
     */
    EXPIRING_SOON(
        isBlocking = false
    ),

    /**
     * RSA key requires policy-specific strength review.
     */
    RSA_KEY_REVIEW_REQUIRED(
        isBlocking = false
    )
}

/**
 * Central constants used by the SentriX certificate subsystem.
 *
 * Kept here as a private implementation companion to avoid requiring
 * another source file for basic certificate constants.
 */
private object CertificateConstants {

    const val X509_TYPE =
        "X.509"

    const val ANDROID_TRUST_STORE =
        "AndroidCAStore"

    const val HASH_SHA_256 =
        "SHA-256"

    const val HASH_SHA_1 =
        "SHA-1"

    const val SERIAL_NUMBER_RADIX =
        16

    const val FINGERPRINT_SEPARATOR =
        ":"

    const val MILLIS_PER_DAY =
        24L * 60L * 60L * 1000L

    const val DEFAULT_EXPIRY_WARNING_DAYS =
        30L

    const val PEM_BEGIN_CERTIFICATE =
        "-----BEGIN CERTIFICATE-----"

    const val PEM_END_CERTIFICATE =
        "-----END CERTIFICATE-----"

    const val SAN_DNS_NAME =
        2

    const val SAN_IP_ADDRESS =
        7

    const val KEY_USAGE_DIGITAL_SIGNATURE =
        0

    const val KEY_USAGE_KEY_ENCIPHERMENT =
        2

    const val TLS_SERVER_AUTH_OID =
        "1.3.6.1.5.5.7.3.1"

    const val TLS_CLIENT_AUTH_OID =
        "1.3.6.1.5.5.7.3.2"

    const val LEGACY_RSA_ALGORITHM =
        "RSA"
}
