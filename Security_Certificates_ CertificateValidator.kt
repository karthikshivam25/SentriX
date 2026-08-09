package com.sentrix.security.certificates

import android.content.Context
import java.security.KeyStore
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.util.Date

/**
 * SentriX Certificate Validator
 *
 * Enterprise-grade X.509 certificate validation component.
 *
 * Responsibilities:
 *
 * - Validate certificate validity periods.
 * - Validate certificate chains.
 * - Validate certificate signatures.
 * - Validate certificate issuer relationships.
 * - Validate certificate key usage.
 * - Validate extended key usage.
 * - Validate Subject Alternative Names.
 * - Validate certificate expiration thresholds.
 * - Validate certificate fingerprints.
 * - Validate certificate policy requirements.
 * - Validate certificates against the Android system trust store.
 *
 * This class DOES NOT:
 *
 * - Disable TLS certificate verification.
 * - Trust self-signed certificates automatically.
 * - Modify Android's system trust store.
 * - Perform SSL pinning.
 * - Manage private keys.
 * - Store certificate secrets.
 * - Replace Android's TLS stack.
 *
 * SSL pinning belongs in the SentriX SSL-pinning subsystem.
 *
 * Architecture:
 *
 *      CertificateManager
 *             │
 *             ▼
 *      CertificateValidator
 *             │
 *       ┌─────┼─────┐
 *       ▼     ▼     ▼
 *    Validity Chain  Policy
 *       │     │     │
 *       └─────┼─────┘
 *             ▼
 *    CertificateValidationResult
 */
class CertificateValidator(
    private val context: Context,
    private val certificateManager: CertificateManager =
        CertificateManager(context)
) {

    /**
     * Application context is retained to avoid keeping an Activity
     * alive accidentally.
     */
    private val applicationContext =
        context.applicationContext

    // =========================================================================
    // Basic Certificate Validation
    // =========================================================================

    /**
     * Performs complete validation using the default SentriX policy.
     */
    fun validate(
        certificate: X509Certificate
    ): CertificateValidationResult {

        return validate(
            certificate = certificate,
            policy = CertificateValidationPolicy.default()
        )
    }

    /**
     * Performs certificate validation using a supplied policy.
     */
    fun validate(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy
    ): CertificateValidationResult {

        val policyValidation =
            validatePolicy(
                policy
            )

        if (
            policyValidation !is
            CertificateValidationResult.Valid
        ) {

            return policyValidation
        }

        val validityResult =
            validateValidity(
                certificate
            )

        if (
            validityResult !is
            CertificateValidationResult.Valid
        ) {

            return validityResult
        }

        val keyResult =
            validatePublicKey(
                certificate,
                policy
            )

        if (
            keyResult !is
            CertificateValidationResult.Valid
        ) {

            return keyResult
        }

        val signatureResult =
            validateSignatureAlgorithm(
                certificate,
                policy
            )

        if (
            signatureResult !is
            CertificateValidationResult.Valid
        ) {

            return signatureResult
        }

        val keyUsageResult =
            validateKeyUsage(
                certificate,
                policy
            )

        if (
            keyUsageResult !is
            CertificateValidationResult.Valid
        ) {

            return keyUsageResult
        }

        val extendedUsageResult =
            validateExtendedKeyUsage(
                certificate,
                policy
            )

        if (
            extendedUsageResult !is
            CertificateValidationResult.Valid
        ) {

            return extendedUsageResult
        }

        return CertificateValidationResult.Valid
    }

    // =========================================================================
    // Policy Validation
    // =========================================================================

    /**
     * Validates the structure of a certificate policy.
     */
    fun validatePolicy(
        policy: CertificateValidationPolicy
    ): CertificateValidationResult {

        if (
            policy.minimumRsaKeySize <
            CertificateConstants.MIN_RSA_KEY_SIZE
        ) {

            return CertificateValidationResult.InvalidPolicy(
                "Minimum RSA key size is too small."
            )
        }

        if (
            policy.minimumEcKeySize <
            CertificateConstants.MIN_EC_KEY_SIZE
        ) {

            return CertificateValidationResult.InvalidPolicy(
                "Minimum EC key size is too small."
            )
        }

        if (
            policy.expiryWarningDays < 0
        ) {

            return CertificateValidationResult.InvalidPolicy(
                "Expiry warning period cannot be negative."
            )
        }

        return CertificateValidationResult.Valid
    }

    // =========================================================================
    // Validity Period
    // =========================================================================

    /**
     * Validates the certificate's current validity period.
     */
    fun validateValidity(
        certificate: X509Certificate,
        validationTime: Date = Date()
    ): CertificateValidationResult {

        return try {

            certificate.checkValidity(
                validationTime
            )

            CertificateValidationResult.Valid

        } catch (
            _: CertificateExpiredException
        ) {

            CertificateValidationResult.Expired(
                certificate.notAfter
            )

        } catch (
            _: CertificateNotYetValidException
        ) {

            CertificateValidationResult.NotYetValid(
                certificate.notBefore
            )

        } catch (
            exception: Exception
        ) {

            CertificateValidationResult.Error(
                exception
            )
        }
    }

    /**
     * Determines whether the certificate will expire within the
     * configured warning period.
     */
    fun validateExpirationWarning(
        certificate: X509Certificate,
        warningDays: Long =
            CertificateConstants.DEFAULT_EXPIRY_WARNING_DAYS
    ): CertificateValidationResult {

        val validity =
            validateValidity(
                certificate
            )

        if (
            validity !is
            CertificateValidationResult.Valid
        ) {

            return validity
        }

        val daysRemaining =
            certificateManager
                .getDaysUntilExpiration(
                    certificate
                )

        return if (
            daysRemaining <= warningDays
        ) {

            CertificateValidationResult.ExpiringSoon(
                daysRemaining
            )

        } else {

            CertificateValidationResult.Valid
        }
    }

    // =========================================================================
    // Public Key Validation
    // =========================================================================

    /**
     * Validates the public-key algorithm and minimum strength.
     */
    fun validatePublicKey(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationResult {

        val algorithm =
            certificate.publicKey
                .algorithm
                .uppercase()

        return when (algorithm) {

            CertificateConstants.RSA_ALGORITHM -> {

                val rsaKeySize =
                    try {

                        (certificate.publicKey
                                as java.security.interfaces.RSAPublicKey)
                            .modulus
                            .bitLength()

                    } catch (
                        exception: Exception
                    ) {

                        return CertificateValidationResult
                            .InvalidPublicKey(
                                "Unable to determine RSA key size.",
                                exception
                            )
                    }

                if (
                    rsaKeySize <
                    policy.minimumRsaKeySize
                ) {

                    CertificateValidationResult
                        .WeakPublicKey(
                            algorithm = algorithm,
                            keySize = rsaKeySize,
                            minimumRequired =
                                policy.minimumRsaKeySize
                        )

                } else {

                    CertificateValidationResult.Valid
                }
            }

            CertificateConstants.EC_ALGORITHM -> {

                val ecKeySize =
                    try {

                        (
                            certificate.publicKey
                                    as java.security.interfaces.ECPublicKey
                            ).params
                            .order
                            .bitLength()

                    } catch (
                        exception: Exception
                    ) {

                        return CertificateValidationResult
                            .InvalidPublicKey(
                                "Unable to determine EC key size.",
                                exception
                            )
                    }

                if (
                    ecKeySize <
                    policy.minimumEcKeySize
                ) {

                    CertificateValidationResult
                        .WeakPublicKey(
                            algorithm = algorithm,
                            keySize = ecKeySize,
                            minimumRequired =
                                policy.minimumEcKeySize
                        )

                } else {

                    CertificateValidationResult.Valid
                }
            }

            else -> {

                if (
                    policy.allowedPublicKeyAlgorithms
                        .none {
                            it.equals(
                                algorithm,
                                ignoreCase = true
                            )
                        }
                ) {

                    CertificateValidationResult.UnsupportedPublicKey(
                        algorithm
                    )

                } else {

                    CertificateValidationResult.Valid
                }
            }
        }
    }

    // =========================================================================
    // Signature Algorithm Validation
    // =========================================================================

    /**
     * Validates the certificate's signature algorithm.
     */
    fun validateSignatureAlgorithm(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationResult {

        val algorithm =
            certificate.sigAlgName

        if (
            policy.disallowedSignatureAlgorithms.any {
                it.equals(
                    algorithm,
                    ignoreCase = true
                )
            }
        ) {

            return CertificateValidationResult
                .DisallowedSignatureAlgorithm(
                    algorithm
                )
        }

        if (
            policy.allowedSignatureAlgorithms.isNotEmpty() &&
            policy.allowedSignatureAlgorithms.none {
                it.equals(
                    algorithm,
                    ignoreCase = true
                )
            }
        ) {

            return CertificateValidationResult
                .UnsupportedSignatureAlgorithm(
                    algorithm
                )
        }

        return CertificateValidationResult.Valid
    }

    // =========================================================================
    // Key Usage Validation
    // =========================================================================

    /**
     * Validates certificate KeyUsage extensions.
     */
    fun validateKeyUsage(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationResult {

        val requiredUsage =
            policy.requiredKeyUsages

        if (
            requiredUsage.isEmpty()
        ) {

            return CertificateValidationResult.Valid
        }

        val keyUsage =
            certificate.keyUsage
                ?: return CertificateValidationResult
                    .MissingKeyUsage

        for (
            usage in requiredUsage
        ) {

            if (
                usage < 0 ||
                usage >= keyUsage.size
            ) {

                return CertificateValidationResult
                    .MissingKeyUsage
            }

            if (
                !keyUsage[usage]
            ) {

                return CertificateValidationResult
                    .InvalidKeyUsage(
                        usage
                    )
            }
        }

        return CertificateValidationResult.Valid
    }

    /**
     * Validates that the certificate supports TLS server authentication.
     */
    fun validateServerAuthenticationUsage(
        certificate: X509Certificate
    ): CertificateValidationResult {

        val extendedKeyUsage =
            certificate.extendedKeyUsage
                ?: return CertificateValidationResult.Valid

        return if (
            CertificateConstants.TLS_SERVER_AUTH_OID
            in extendedKeyUsage
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.InvalidExtendedKeyUsage(
                "TLS server authentication usage is missing."
            )
        }
    }

    /**
     * Validates TLS client authentication usage.
     */
    fun validateClientAuthenticationUsage(
        certificate: X509Certificate
    ): CertificateValidationResult {

        val extendedKeyUsage =
            certificate.extendedKeyUsage
                ?: return CertificateValidationResult.Valid

        return if (
            CertificateConstants.TLS_CLIENT_AUTH_OID
            in extendedKeyUsage
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.InvalidExtendedKeyUsage(
                "TLS client authentication usage is missing."
            )
        }
    }

    // =========================================================================
    // Extended Key Usage
    // =========================================================================

    /**
     * Validates extended key usage requirements.
     */
    fun validateExtendedKeyUsage(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationResult {

        if (
            policy.requiredExtendedKeyUsages.isEmpty()
        ) {

            return CertificateValidationResult.Valid
        }

        val certificateUsages =
            certificate.extendedKeyUsage
                ?: return CertificateValidationResult
                    .MissingExtendedKeyUsage

        for (
            requiredUsage in
                policy.requiredExtendedKeyUsages
        ) {

            if (
                requiredUsage !in certificateUsages
            ) {

                return CertificateValidationResult
                    .InvalidExtendedKeyUsage(
                        "Required extended key usage is missing: " +
                                requiredUsage
                    )
            }
        }

        return CertificateValidationResult.Valid
    }

    // =========================================================================
    // Subject Alternative Name
    // =========================================================================

    /**
     * Validates whether a DNS hostname is represented in the
     * certificate's Subject Alternative Name extension.
     *
     * This performs exact and wildcard-aware hostname matching.
     */
    fun validateHostname(
        certificate: X509Certificate,
        hostname: String
    ): CertificateValidationResult {

        if (
            hostname.isBlank()
        ) {

            return CertificateValidationResult.InvalidHostname(
                "Hostname must not be blank."
            )
        }

        val dnsNames =
            certificateManager.getDnsNames(
                certificate
            )

        val normalizedHostname =
            hostname
                .trim()
                .lowercase()

        val matches =
            dnsNames.any {
                matchesHostname(
                    certificateName =
                        it.lowercase(),
                    hostname =
                        normalizedHostname
                )
            }

        return if (
            matches
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.HostnameMismatch(
                hostname
            )
        }
    }

    /**
     * Performs conservative DNS wildcard matching.
     *
     * A wildcard may represent one complete left-most DNS label only.
     *
     * Example:
     *
     *      *.example.com
     *
     * matches:
     *
     *      api.example.com
     *
     * but does not match:
     *
     *      deep.api.example.com
     */
    private fun matchesHostname(
        certificateName: String,
        hostname: String
    ): Boolean {

        if (
            certificateName == hostname
        ) {

            return true
        }

        if (
            !certificateName.startsWith(
                "*."
            )
        ) {

            return false
        }

        val suffix =
            certificateName.substring(
                1
            )

        if (
            !hostname.endsWith(
                suffix
            )
        ) {

            return false
        }

        val prefix =
            hostname.removeSuffix(
                suffix
            )

        return prefix.isNotEmpty() &&
                !prefix.contains(".")
    }

    /**
     * Validates an IP address against the certificate SAN extension.
     */
    fun validateIpAddress(
        certificate: X509Certificate,
        ipAddress: String
    ): CertificateValidationResult {

        if (
            ipAddress.isBlank()
        ) {

            return CertificateValidationResult.InvalidHostname(
                "IP address must not be blank."
            )
        }

        val certificateIps =
            certificateManager.getIpAddresses(
                certificate
            )

        return if (
            certificateIps.any {
                it.equals(
                    ipAddress.trim(),
                    ignoreCase = true
                )
            }
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.HostnameMismatch(
                ipAddress
            )
        }
    }

    // =========================================================================
    // Fingerprint Validation
    // =========================================================================

    /**
     * Validates a certificate against a SHA-256 fingerprint.
     *
     * This is useful for certificate identity checks and can also
     * support the dedicated SSL-pinning layer.
     */
    fun validateSha256Fingerprint(
        certificate: X509Certificate,
        expectedFingerprint: String
    ): CertificateValidationResult {

        if (
            expectedFingerprint.isBlank()
        ) {

            return CertificateValidationResult.InvalidFingerprint(
                "Expected fingerprint must not be blank."
            )
        }

        return if (
            certificateManager.matchesSha256Fingerprint(
                certificate = certificate,
                expectedFingerprint =
                    expectedFingerprint
            )
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.FingerprintMismatch
        }
    }

    /**
     * Validates multiple allowed SHA-256 fingerprints.
     */
    fun validateSha256Fingerprint(
        certificate: X509Certificate,
        allowedFingerprints: Collection<String>
    ): CertificateValidationResult {

        if (
            allowedFingerprints.isEmpty()
        ) {

            return CertificateValidationResult
                .InvalidFingerprint(
                    "At least one fingerprint must be supplied."
                )
        }

        val actualFingerprint =
            certificateManager
                .getSha256Fingerprint(
                    certificate
                )

        val matches =
            allowedFingerprints.any {
                normalizeFingerprint(
                    it
                ) ==
                        normalizeFingerprint(
                            actualFingerprint
                        )
            }

        return if (
            matches
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.FingerprintMismatch
        }
    }

    /**
     * Normalizes a certificate fingerprint for comparison.
     */
    private fun normalizeFingerprint(
        fingerprint: String
    ): String {

        return fingerprint
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
    }

    // =========================================================================
    // Certificate Chain Validation
    // =========================================================================

    /**
     * Validates basic ordering and validity of a certificate chain.
     *
     * This does not replace complete PKIX validation.
     */
    fun validateChain(
        certificateChain: List<X509Certificate>
    ): CertificateValidationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateValidationResult
                .InvalidChain(
                    "Certificate chain must not be empty."
                )
        }

        if (
            !certificateManager.isChainOrdered(
                certificateChain
            )
        ) {

            return CertificateValidationResult
                .InvalidChain(
                    "Certificate chain signature relationships are invalid."
                )
        }

        if (
            !certificateManager.isChainCurrentlyValid(
                certificateChain
            )
        ) {

            return CertificateValidationResult
                .InvalidChain(
                    "One or more certificates in the chain are outside " +
                            "their validity period."
                )
        }

        return CertificateValidationResult.Valid
    }

    /**
     * Performs complete PKIX path validation against the Android
     * system trust store.
     *
     * The chain should be ordered leaf -> issuer -> root/intermediate.
     */
    fun validateTrustedChain(
        certificateChain: List<X509Certificate>
    ): CertificateValidationResult {

        val basicValidation =
            validateChain(
                certificateChain
            )

        if (
            basicValidation !is
            CertificateValidationResult.Valid
        ) {

            return basicValidation
        }

        return try {

            val certificateFactory =
                CertificateFactory.getInstance(
                    CertificateConstants.X509_TYPE
                )

            val certPath =
                certificateFactory.generateCertPath(
                    certificateChain
                )

            val trustStore =
                KeyStore.getInstance(
                    CertificateConstants.ANDROID_TRUST_STORE
                ).apply {

                    load(
                        null
                    )
                }

            val trustAnchors =
                trustStore
                    .aliases()
                    .asSequence()
                    .mapNotNull { alias ->

                        trustStore
                            .getCertificate(
                                alias
                            ) as? X509Certificate

                    }
                    .map {
                        TrustAnchor(
                            it,
                            null
                        )
                    }
                    .toSet()

            if (
                trustAnchors.isEmpty()
            ) {

                return CertificateValidationResult
                    .TrustStoreUnavailable
            }

            val parameters =
                PKIXParameters(
                    trustAnchors
                ).apply {

                    isRevocationEnabled =
                        false
                }

            CertPathValidator
                .getInstance(
                    CertificateConstants.PKIX
                )
                .validate(
                    certPath,
                    parameters
                )

            CertificateValidationResult.Valid

        } catch (
            exception: CertificateException
        ) {

            CertificateValidationResult
                .UntrustedCertificate(
                    exception.message
                        ?: "Certificate path is not trusted."
                )

        } catch (
            exception: Exception
        ) {

            CertificateValidationResult.Error(
                exception
            )
        }
    }

    // =========================================================================
    // Issuer Validation
    // =========================================================================

    /**
     * Validates that a certificate was signed by the supplied issuer.
     */
    fun validateIssuer(
        certificate: X509Certificate,
        issuer: X509Certificate
    ): CertificateValidationResult {

        return try {

            certificate.verify(
                issuer.publicKey
            )

            CertificateValidationResult.Valid

        } catch (
            exception: Exception
        ) {

            CertificateValidationResult.InvalidIssuer(
                exception.message
                    ?: "Certificate signature verification failed."
            )
        }
    }

    // =========================================================================
    // Certificate Type Validation
    // =========================================================================

    /**
     * Validates whether the certificate is an end-entity certificate.
     */
    fun validateEndEntity(
        certificate: X509Certificate
    ): CertificateValidationResult {

        return if (
            certificate.basicConstraints < 0
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.UnexpectedCertificateType(
                "Certificate is a CA certificate, not an end-entity certificate."
            )
        }
    }

    /**
     * Validates whether the certificate is a CA certificate.
     */
    fun validateCertificateAuthority(
        certificate: X509Certificate
    ): CertificateValidationResult {

        return if (
            certificate.basicConstraints >= 0
        ) {

            CertificateValidationResult.Valid

        } else {

            CertificateValidationResult.UnexpectedCertificateType(
                "Certificate is not a certificate authority."
            )
        }
    }

    // =========================================================================
    // Comprehensive Server Certificate Validation
    // =========================================================================

    /**
     * Performs a comprehensive TLS server certificate validation.
     *
     * This includes:
     *
     * - Certificate validity.
     * - Public key policy.
     * - Signature algorithm.
     * - Key usage.
     * - Extended key usage.
     * - Hostname/SAN validation.
     */
    fun validateServerCertificate(
        certificate: X509Certificate,
        hostname: String,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationResult {

        val baseResult =
            validate(
                certificate = certificate,
                policy = policy
            )

        if (
            baseResult !is
            CertificateValidationResult.Valid
        ) {

            return baseResult
        }

        val serverUsageResult =
            validateServerAuthenticationUsage(
                certificate
            )

        if (
            serverUsageResult !is
            CertificateValidationResult.Valid
        ) {

            return serverUsageResult
        }

        return validateHostname(
            certificate = certificate,
            hostname = hostname
        )
    }

    // =========================================================================
    // Certificate Security Assessment
    // =========================================================================

    /**
     * Converts validation results into a security assessment.
     */
    fun assessSecurity(
        certificate: X509Certificate,
        policy: CertificateValidationPolicy =
            CertificateValidationPolicy.default()
    ): CertificateValidationAssessment {

        val results =
            mutableListOf<CertificateValidationResult>()

        results +=
            validateValidity(
                certificate
            )

        results +=
            validatePublicKey(
                certificate,
                policy
            )

        results +=
            validateSignatureAlgorithm(
                certificate,
                policy
            )

        results +=
            validateKeyUsage(
                certificate,
                policy
            )

        results +=
            validateExtendedKeyUsage(
                certificate,
                policy
            )

        val blockingIssues =
            results.filter {
                it !is
                        CertificateValidationResult.Valid &&
                        it.isBlocking
            }

        val warnings =
            results.filter {
                it !is
                        CertificateValidationResult.Valid &&
                        !it.isBlocking
            }

        return CertificateValidationAssessment(
            valid =
                blockingIssues.isEmpty(),

            blockingIssues =
                blockingIssues,

            warnings =
                warnings
        )
    }
}

/**
 * Certificate validation policy used by SentriX.
 */
data class CertificateValidationPolicy(
    val minimumRsaKeySize: Int,
    val minimumEcKeySize: Int,

    val expiryWarningDays: Long,

    val allowedPublicKeyAlgorithms: Set<String>,

    val allowedSignatureAlgorithms: Set<String>,

    val disallowedSignatureAlgorithms: Set<String>,

    val requiredKeyUsages: Set<Int>,

    val requiredExtendedKeyUsages: Set<String>
) {

    companion object {

        /**
         * Default enterprise-oriented SentriX certificate policy.
         *
         * The policy intentionally does not automatically reject every
         * certificate using an algorithm not explicitly listed. Such
         * decisions should be made deliberately for the deployment
         * environment.
         */
        fun default():
                CertificateValidationPolicy {

            return CertificateValidationPolicy(

                minimumRsaKeySize =
                    CertificateConstants.MIN_RSA_KEY_SIZE,

                minimumEcKeySize =
                    CertificateConstants.MIN_EC_KEY_SIZE,

                expiryWarningDays =
                    CertificateConstants
                        .DEFAULT_EXPIRY_WARNING_DAYS,

                allowedPublicKeyAlgorithms =
                    setOf(
                        CertificateConstants.RSA_ALGORITHM,
                        CertificateConstants.EC_ALGORITHM
                    ),

                allowedSignatureAlgorithms =
                    emptySet(),

                disallowedSignatureAlgorithms =
                    setOf(
                        CertificateConstants.MD5_WITH_RSA,
                        CertificateConstants.SHA1_WITH_RSA
                    ),

                requiredKeyUsages =
                    emptySet(),

                requiredExtendedKeyUsages =
                    emptySet()
            )
        }

        /**
         * Policy specifically designed for TLS server certificates.
         */
        fun tlsServer():
                CertificateValidationPolicy {

            return default().copy(

                requiredKeyUsages =
                    setOf(
                        CertificateConstants
                            .KEY_USAGE_DIGITAL_SIGNATURE
                    ),

                requiredExtendedKeyUsages =
                    setOf(
                        CertificateConstants
                            .TLS_SERVER_AUTH_OID
                    )
            )
        }

        /**
         * Strict high-security certificate policy.
         */
        fun highSecurity():
                CertificateValidationPolicy {

            return default().copy(

                minimumRsaKeySize =
                    CertificateConstants
                        .STRICT_MIN_RSA_KEY_SIZE,

                minimumEcKeySize =
                    CertificateConstants
                        .STRICT_MIN_EC_KEY_SIZE,

                expiryWarningDays =
                    CertificateConstants
                        .STRICT_EXPIRY_WARNING_DAYS,

                disallowedSignatureAlgorithms =
                    setOf(
                        CertificateConstants.MD5_WITH_RSA,
                        CertificateConstants.SHA1_WITH_RSA
                    )
            )
        }
    }
}

/**
 * Result returned by certificate validation operations.
 */
sealed class CertificateValidationResult {

    /**
     * Certificate satisfies the requested validation.
     */
    data object Valid :
        CertificateValidationResult()

    /**
     * Certificate has expired.
     */
    data class Expired(
        val expirationDate: Date
    ) : CertificateValidationResult()

    /**
     * Certificate validity period has not started.
     */
    data class NotYetValid(
        val validFrom: Date
    ) : CertificateValidationResult()

    /**
     * Certificate is approaching expiration.
     */
    data class ExpiringSoon(
        val daysRemaining: Long
    ) : CertificateValidationResult()

    /**
     * Public key is weaker than the configured policy.
     */
    data class WeakPublicKey(
        val algorithm: String,
        val keySize: Int,
        val minimumRequired: Int
    ) : CertificateValidationResult()

    /**
     * Public key could not be interpreted.
     */
    data class InvalidPublicKey(
        val reason: String,
        val cause: Throwable? = null
    ) : CertificateValidationResult()

    /**
     * Public-key algorithm is unsupported.
     */
    data class UnsupportedPublicKey(
        val algorithm: String
    ) : CertificateValidationResult()

    /**
     * Signature algorithm is explicitly disallowed.
     */
    data class DisallowedSignatureAlgorithm(
        val algorithm: String
    ) : CertificateValidationResult()

    /**
     * Signature algorithm is not permitted by policy.
     */
    data class UnsupportedSignatureAlgorithm(
        val algorithm: String
    ) : CertificateValidationResult()

    /**
     * Certificate does not contain the required KeyUsage extension.
     */
    data object MissingKeyUsage :
        CertificateValidationResult()

    /**
     * Certificate does not contain the required key-usage bit.
     */
    data class InvalidKeyUsage(
        val usageIndex: Int
    ) : CertificateValidationResult()

    /**
     * Required Extended Key Usage is missing.
     */
    data object MissingExtendedKeyUsage :
        CertificateValidationResult()

    /**
     * Extended Key Usage requirement was not satisfied.
     */
    data class InvalidExtendedKeyUsage(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Hostname does not match certificate SAN.
     */
    data class HostnameMismatch(
        val hostname: String
    ) : CertificateValidationResult()

    /**
     * Supplied fingerprint is malformed or empty.
     */
    data class InvalidFingerprint(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Certificate fingerprint does not match.
     */
    data object FingerprintMismatch :
        CertificateValidationResult()

    /**
     * Certificate chain is malformed or invalid.
     */
    data class InvalidChain(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Certificate is not trusted by the configured platform trust
     * anchors.
     */
    data class UntrustedCertificate(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Platform trust store could not be accessed.
     */
    data object TrustStoreUnavailable :
        CertificateValidationResult()

    /**
     * Certificate was signed by an unexpected issuer.
     */
    data class InvalidIssuer(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Certificate type is not appropriate for the requested operation.
     */
    data class UnexpectedCertificateType(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Hostname input itself is invalid.
     */
    data class InvalidHostname(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Validation policy is invalid.
     */
    data class InvalidPolicy(
        val reason: String
    ) : CertificateValidationResult()

    /**
     * Unexpected validation error.
     */
    data class Error(
        val cause: Throwable
    ) : CertificateValidationResult()

    /**
     * Unknown validation state.
     */
    data object Unknown :
        CertificateValidationResult()

    /**
     * Indicates whether the result should block a security-sensitive
     * operation.
     */
    val isBlocking: Boolean
        get() = when (this) {

            Valid ->
                false

            is ExpiringSoon ->
                false

            is Expired ->
                true

            is NotYetValid ->
                true

            is WeakPublicKey ->
                true

            is InvalidPublicKey ->
                true

            is UnsupportedPublicKey ->
                true

            is DisallowedSignatureAlgorithm ->
                true

            is UnsupportedSignatureAlgorithm ->
                true

            MissingKeyUsage ->
                true

            is InvalidKeyUsage ->
                true

            MissingExtendedKeyUsage ->
                true

            is InvalidExtendedKeyUsage ->
                true

            is HostnameMismatch ->
                true

            is InvalidFingerprint ->
                true

            FingerprintMismatch ->
                true

            is InvalidChain ->
                true

            is UntrustedCertificate ->
                true

            TrustStoreUnavailable ->
                true

            is InvalidIssuer ->
                true

            is UnexpectedCertificateType ->
                true

            is InvalidHostname ->
                true

            is InvalidPolicy ->
                true

            is Error ->
                true

            Unknown ->
                true
        }
}

/**
 * High-level certificate validation assessment.
 */
data class CertificateValidationAssessment(
    val valid: Boolean,
    val blockingIssues:
        List<CertificateValidationResult>,
    val warnings:
        List<CertificateValidationResult>
)

/**
 * Internal constants for certificate validation.
 */
private object CertificateConstants {

    const val X509_TYPE =
        "X.509"

    const val PKIX =
        "PKIX"

    const val ANDROID_TRUST_STORE =
        "AndroidCAStore"

    // -------------------------------------------------------------------------
    // Public Key Algorithms
    // -------------------------------------------------------------------------

    const val RSA_ALGORITHM =
        "RSA"

    const val EC_ALGORITHM =
        "EC"

    // -------------------------------------------------------------------------
    // Key Strength
    // -------------------------------------------------------------------------

    /**
     * Modern baseline RSA key size.
     */
    const val MIN_RSA_KEY_SIZE =
        2048

    /**
     * Modern baseline EC key size.
     */
    const val MIN_EC_KEY_SIZE =
        256

    /**
     * High-security RSA baseline.
     */
    const val STRICT_MIN_RSA_KEY_SIZE =
        3072

    /**
     * High-security EC baseline.
     */
    const val STRICT_MIN_EC_KEY_SIZE =
        256

    // -------------------------------------------------------------------------
    // Expiration
    // -------------------------------------------------------------------------

    const val DEFAULT_EXPIRY_WARNING_DAYS =
        30L

    const val STRICT_EXPIRY_WARNING_DAYS =
        14L

    // -------------------------------------------------------------------------
    // Signature Algorithms
    // -------------------------------------------------------------------------

    const val MD5_WITH_RSA =
        "MD5withRSA"

    const val SHA1_WITH_RSA =
        "SHA1withRSA"

    // -------------------------------------------------------------------------
    // Extended Key Usage
    // -------------------------------------------------------------------------

    const val TLS_SERVER_AUTH_OID =
        "1.3.6.1.5.5.7.3.1"

    // -------------------------------------------------------------------------
    // Key Usage
    // -------------------------------------------------------------------------

    const val KEY_USAGE_DIGITAL_SIGNATURE =
        0
}
