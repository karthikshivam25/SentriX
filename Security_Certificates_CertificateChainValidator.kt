package com.sentrix.security.certificates

import android.content.Context
import java.security.KeyStore
import java.security.cert.CertPath
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.util.Date

/**
 * SentriX Certificate Chain Validator
 *
 * Enterprise-grade X.509 certificate-chain validation component.
 *
 * Responsibilities:
 *
 * - Validate certificate-chain structure.
 * - Validate leaf -> issuer relationships.
 * - Validate certificate validity periods.
 * - Validate CA constraints.
 * - Validate certificate path length constraints.
 * - Validate certificate signatures.
 * - Validate the chain against Android's trusted CA store.
 * - Detect broken chains.
 * - Detect incomplete chains.
 * - Detect invalid issuer relationships.
 * - Detect expired certificates within the chain.
 * - Validate leaf certificate requirements.
 *
 * This class DOES NOT:
 *
 * - Disable certificate validation.
 * - Automatically trust self-signed certificates.
 * - Modify Android's trust store.
 * - Implement SSL pinning.
 * - Store private keys.
 * - Replace Android's TLS implementation.
 *
 * SSL pinning belongs to SentriX's dedicated sslpinning subsystem.
 *
 * Expected chain order:
 *
 *      Leaf
 *        │
 *        ▼
 *   Intermediate
 *        │
 *        ▼
 *      Root
 *
 * The input list should therefore normally be:
 *
 *      [leaf, intermediate, root]
 *
 * Architecture:
 *
 *      CertificateParser
 *             │
 *             ▼
 *      CertificateChainValidator
 *             │
 *       ┌─────┼──────┐
 *       ▼     ▼      ▼
 *    Structure PKIX  CA Rules
 *       │     │      │
 *       └─────┼──────┘
 *             ▼
 *      ChainValidationResult
 */
class CertificateChainValidator(
    context: Context,
    private val certificateManager: CertificateManager =
        CertificateManager(context),
    private val certificateValidator: CertificateValidator =
        CertificateValidator(
            context = context,
            certificateManager = certificateManager
        )
) {

    private val applicationContext =
        context.applicationContext

    // =========================================================================
    // Main Validation
    // =========================================================================

    /**
     * Performs complete chain validation using the default SentriX policy.
     */
    fun validate(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        return validate(
            certificateChain = certificateChain,
            policy =
                CertificateChainValidationPolicy.default()
        )
    }

    /**
     * Performs complete certificate-chain validation.
     */
    fun validate(
        certificateChain: List<X509Certificate>,
        policy: CertificateChainValidationPolicy
    ): CertificateChainValidationResult {

        // ---------------------------------------------------------------------
        // Policy validation
        // ---------------------------------------------------------------------

        val policyResult =
            validatePolicy(
                policy
            )

        if (
            policyResult !is
            CertificateChainValidationResult.Valid
        ) {

            return policyResult
        }

        // ---------------------------------------------------------------------
        // Empty chain
        // ---------------------------------------------------------------------

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainValidationResult
                .EmptyChain
        }

        // ---------------------------------------------------------------------
        // Chain size
        // ---------------------------------------------------------------------

        if (
            certificateChain.size >
            policy.maxChainLength
        ) {

            return CertificateChainValidationResult
                .ChainTooLong(
                    actualLength =
                        certificateChain.size,
                    maximumLength =
                        policy.maxChainLength
                )
        }

        // ---------------------------------------------------------------------
        // Duplicate detection
        // ---------------------------------------------------------------------

        if (
            containsDuplicates(
                certificateChain
            )
        ) {

            return CertificateChainValidationResult
                .DuplicateCertificates
        }

        // ---------------------------------------------------------------------
        // Structure
        // ---------------------------------------------------------------------

        val structureResult =
            validateStructure(
                certificateChain
            )

        if (
            structureResult !is
            CertificateChainValidationResult.Valid
        ) {

            return structureResult
        }

        // ---------------------------------------------------------------------
        // Individual certificate validity
        // ---------------------------------------------------------------------

        val validityResult =
            validateCertificateValidity(
                certificateChain
            )

        if (
            validityResult !is
            CertificateChainValidationResult.Valid
        ) {

            return validityResult
        }

        // ---------------------------------------------------------------------
        // Issuer relationships
        // ---------------------------------------------------------------------

        val issuerResult =
            validateIssuerRelationships(
                certificateChain
            )

        if (
            issuerResult !is
            CertificateChainValidationResult.Valid
        ) {

            return issuerResult
        }

        // ---------------------------------------------------------------------
        // CA constraints
        // ---------------------------------------------------------------------

        val caResult =
            validateCaConstraints(
                certificateChain
            )

        if (
            caResult !is
            CertificateChainValidationResult.Valid
        ) {

            return caResult
        }

        // ---------------------------------------------------------------------
        // Path length constraints
        // ---------------------------------------------------------------------

        val pathLengthResult =
            validatePathLengthConstraints(
                certificateChain
            )

        if (
            pathLengthResult !is
            CertificateChainValidationResult.Valid
        ) {

            return pathLengthResult
        }

        // ---------------------------------------------------------------------
        // Certificate policy
        // ---------------------------------------------------------------------

        val certificatePolicyResult =
            validateCertificatesAgainstPolicy(
                certificateChain,
                policy
            )

        if (
            certificatePolicyResult !is
            CertificateChainValidationResult.Valid
        ) {

            return certificatePolicyResult
        }

        // ---------------------------------------------------------------------
        // Platform trust
        // ---------------------------------------------------------------------

        if (
            policy.requireSystemTrust
        ) {

            val trustResult =
                validateAgainstSystemTrustStore(
                    certificateChain
                )

            if (
                trustResult !is
                CertificateChainValidationResult.Valid
            ) {

                return trustResult
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Policy Validation
    // =========================================================================

    /**
     * Validates the chain-validation policy itself.
     */
    fun validatePolicy(
        policy: CertificateChainValidationPolicy
    ): CertificateChainValidationResult {

        if (
            policy.maxChainLength <
            CertificateChainValidationConstants
                .MIN_CHAIN_LENGTH
        ) {

            return CertificateChainValidationResult
                .InvalidPolicy(
                    "Maximum chain length is too small."
                )
        }

        if (
            policy.maxChainLength >
            CertificateChainValidationConstants
                .ABSOLUTE_MAX_CHAIN_LENGTH
        ) {

            return CertificateChainValidationResult
                .InvalidPolicy(
                    "Maximum chain length exceeds SentriX safety limit."
                )
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Chain Structure
    // =========================================================================

    /**
     * Validates the basic structure of the supplied chain.
     *
     * Expected order:
     *
     *      [leaf, intermediate..., root]
     */
    fun validateStructure(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainValidationResult.EmptyChain
        }

        // ---------------------------------------------------------------------
        // Leaf validation
        // ---------------------------------------------------------------------

        val leaf =
            certificateChain.first()

        if (
            leaf.basicConstraints >= 0
        ) {

            return CertificateChainValidationResult
                .InvalidLeafCertificate(
                    "The first certificate in the chain must be an " +
                            "end-entity certificate."
                )
        }

        // ---------------------------------------------------------------------
        // Intermediate/root validation
        // ---------------------------------------------------------------------

        if (
            certificateChain.size > 1
        ) {

            for (
                index in 1 until
                        certificateChain.size
            ) {

                val certificate =
                    certificateChain[index]

                if (
                    certificate.basicConstraints < 0
                ) {

                    return CertificateChainValidationResult
                        .InvalidCertificateAuthority(
                            index = index,
                            reason =
                                "Non-leaf certificate is not a CA certificate."
                        )
                }
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Duplicate Detection
    // =========================================================================

    /**
     * Determines whether the chain contains duplicate certificates.
     */
    fun containsDuplicates(
        certificateChain: List<X509Certificate>
    ): Boolean {

        val fingerprints =
            mutableSetOf<String>()

        for (
            certificate in certificateChain
        ) {

            val fingerprint =
                certificateManager
                    .getSha256Fingerprint(
                        certificate
                    )

            if (
                !fingerprints.add(
                    fingerprint
                )
            ) {

                return true
            }
        }

        return false
    }

    // =========================================================================
    // Certificate Validity
    // =========================================================================

    /**
     * Validates the validity period of every certificate in the chain.
     */
    fun validateCertificateValidity(
        certificateChain: List<X509Certificate>,
        validationTime: Date = Date()
    ): CertificateChainValidationResult {

        for (
            index in certificateChain.indices
        ) {

            val certificate =
                certificateChain[index]

            val result =
                certificateValidator
                    .validateValidity(
                        certificate = certificate,
                        validationTime =
                            validationTime
                    )

            when (result) {

                CertificateValidationResult.Valid -> {
                    // Continue.
                }

                is CertificateValidationResult.Expired -> {

                    return CertificateChainValidationResult
                        .ExpiredCertificate(
                            index = index,
                            expirationDate =
                                result.expirationDate
                        )
                }

                is CertificateValidationResult.NotYetValid -> {

                    return CertificateChainValidationResult
                        .NotYetValidCertificate(
                            index = index,
                            validFrom =
                                result.validFrom
                        )
                }

                else -> {

                    return CertificateChainValidationResult
                        .CertificateValidationFailed(
                            index = index,
                            reason =
                                result.toString()
                        )
                }
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Issuer Relationships
    // =========================================================================

    /**
     * Validates each certificate against the next certificate in the chain.
     *
     * Example:
     *
     *      leaf.verify(intermediate.publicKey)
     *      intermediate.verify(root.publicKey)
     */
    fun validateIssuerRelationships(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.size <= 1
        ) {

            return CertificateChainValidationResult.Valid
        }

        for (
            index in 0 until
                    certificateChain.size - 1
        ) {

            val certificate =
                certificateChain[index]

            val issuer =
                certificateChain[index + 1]

            // -----------------------------------------------------------------
            // Distinguished-name relationship
            // -----------------------------------------------------------------

            if (
                certificate.issuerX500Principal !=
                issuer.subjectX500Principal
            ) {

                return CertificateChainValidationResult
                    .IssuerMismatch(
                        certificateIndex =
                            index,
                        issuerIndex =
                            index + 1
                    )
            }

            // -----------------------------------------------------------------
            // Cryptographic signature relationship
            // -----------------------------------------------------------------

            if (
                !certificateManager.verifySignedBy(
                    certificate = certificate,
                    issuer = issuer
                )
            ) {

                return CertificateChainValidationResult
                    .SignatureVerificationFailed(
                        certificateIndex =
                            index,
                        issuerIndex =
                            index + 1
                    )
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // CA Constraints
    // =========================================================================

    /**
     * Validates that all non-leaf certificates are legitimate CA
     * certificates.
     */
    fun validateCaConstraints(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.size <= 1
        ) {

            return CertificateChainValidationResult.Valid
        }

        for (
            index in 1 until
                    certificateChain.size
        ) {

            val certificate =
                certificateChain[index]

            if (
                certificate.basicConstraints < 0
            ) {

                return CertificateChainValidationResult
                    .InvalidCertificateAuthority(
                        index = index,
                        reason =
                            "Certificate does not contain CA basic constraints."
                    )
            }

            val keyUsage =
                certificate.keyUsage

            /**
             * If KeyUsage is present, keyCertSign must be enabled
             * for a certificate acting as a CA in this chain.
             */
            if (
                keyUsage != null
            ) {

                val keyCertSignIndex =
                    CertificateChainValidationConstants
                        .KEY_USAGE_KEY_CERT_SIGN

                if (
                    keyUsage.size <=
                    keyCertSignIndex ||
                    !keyUsage[keyCertSignIndex]
                ) {

                    return CertificateChainValidationResult
                        .InvalidCertificateAuthority(
                            index = index,
                            reason =
                                "CA certificate does not permit certificate signing."
                        )
                }
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Path Length Constraints
    // =========================================================================

    /**
     * Validates BasicConstraints pathLenConstraint values.
     *
     * The check is performed from the leaf toward the root.
     */
    fun validatePathLengthConstraints(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.size <= 1
        ) {

            return CertificateChainValidationResult.Valid
        }

        for (
            issuerIndex in 1 until
                    certificateChain.size
        ) {

            val issuer =
                certificateChain[issuerIndex]

            val pathLength =
                issuer.basicConstraints

            if (
                pathLength < 0
            ) {

                return CertificateChainValidationResult
                    .InvalidCertificateAuthority(
                        index = issuerIndex,
                        reason =
                            "Certificate is not a valid CA."
                    )
            }

            /**
             * Number of CA certificates below the current issuer.
             */
            var caCertificatesBelow =
                0

            for (
                belowIndex in
                    1 until issuerIndex
            ) {

                if (
                    certificateChain[
                        belowIndex
                    ].basicConstraints >= 0
                ) {

                    caCertificatesBelow++
                }
            }

            if (
                pathLength <
                caCertificatesBelow
            ) {

                return CertificateChainValidationResult
                    .PathLengthConstraintExceeded(
                        certificateIndex =
                            issuerIndex,
                        maximum =
                            pathLength,
                        actual =
                            caCertificatesBelow
                    )
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Certificate Policy
    // =========================================================================

    /**
     * Applies CertificateValidator policy to each certificate.
     */
    fun validateCertificatesAgainstPolicy(
        certificateChain: List<X509Certificate>,
        policy: CertificateChainValidationPolicy
    ): CertificateChainValidationResult {

        for (
            index in certificateChain.indices
        ) {

            val certificate =
                certificateChain[index]

            val certificatePolicy =
                policy.certificatePolicy

            val result =
                certificateValidator.validate(
                    certificate =
                        certificate,
                    policy =
                        certificatePolicy
                )

            if (
                result !is
                CertificateValidationResult.Valid
            ) {

                return CertificateChainValidationResult
                    .CertificateValidationFailed(
                        index = index,
                        reason =
                            result.toString()
                    )
            }
        }

        return CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // System Trust Validation
    // =========================================================================

    /**
     * Validates the certificate chain against Android's system trust
     * anchors using PKIX.
     *
     * Revocation checking is deliberately not enabled here because
     * Android's trust configuration and the application's network
     * security strategy may determine how revocation is handled.
     *
     * This method must never be interpreted as certificate pinning.
     */
    fun validateAgainstSystemTrustStore(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainValidationResult.EmptyChain
        }

        return try {

            val certificateFactory =
                CertificateFactory.getInstance(
                    CertificateChainValidationConstants
                        .X509_TYPE
                )

            val certPath =
                certificateFactory
                    .generateCertPath(
                        certificateChain
                    )

            val trustStore =
                KeyStore.getInstance(
                    CertificateChainValidationConstants
                        .ANDROID_TRUST_STORE
                ).apply {

                    load(
                        null
                    )
                }

            val trustAnchors =
                buildTrustAnchors(
                    trustStore
                )

            if (
                trustAnchors.isEmpty()
            ) {

                return CertificateChainValidationResult
                    .TrustStoreUnavailable
            }

            val parameters =
                PKIXParameters(
                    trustAnchors
                ).apply {

                    /**
                     * Revocation policy is intentionally delegated to
                     * the broader SentriX/network security architecture.
                     */
                    isRevocationEnabled =
                        false
                }

            val validator =
                CertPathValidator
                    .getInstance(
                        CertificateChainValidationConstants
                            .PKIX
                    )

            validator.validate(
                certPath,
                parameters
            )

            CertificateChainValidationResult.Valid

        } catch (
            exception: java.security.cert.CertPathValidatorException
        ) {

            CertificateChainValidationResult
                .TrustValidationFailed(
                    reason =
                        exception.message
                            ?: "PKIX validation failed."
                )

        } catch (
            exception: CertificateException
        ) {

            CertificateChainValidationResult
                .TrustValidationFailed(
                    reason =
                        exception.message
                            ?: "Certificate path validation failed."
                )

        } catch (
            exception: Exception
        ) {

            CertificateChainValidationResult.Error(
                exception
            )
        }
    }

    /**
     * Converts certificates from the Android trust store into
     * TrustAnchor instances.
     */
    private fun buildTrustAnchors(
        trustStore: KeyStore
    ): Set<TrustAnchor> {

        val trustAnchors =
            mutableSetOf<TrustAnchor>()

        val aliases =
            trustStore.aliases()

        while (
            aliases.hasMoreElements()
        ) {

            val alias =
                aliases.nextElement()

            val certificate =
                trustStore.getCertificate(
                    alias
                ) as? X509Certificate
                    ?: continue

            trustAnchors +=
                TrustAnchor(
                    certificate,
                    null
                )
        }

        return trustAnchors
    }

    // =========================================================================
    // Root Certificate Validation
    // =========================================================================

    /**
     * Validates the root certificate at the end of the supplied chain.
     */
    fun validateRootCertificate(
        certificateChain: List<X509Certificate>
    ): CertificateChainValidationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainValidationResult.EmptyChain
        }

        val root =
            certificateChain.last()

        if (
            root.basicConstraints < 0
        ) {

            return CertificateChainValidationResult
                .InvalidRootCertificate(
                    "The last certificate must be a CA certificate."
                )
        }

        /**
         * If the root has a KeyUsage extension, keyCertSign should
         * be present.
         */
        val keyUsage =
            root.keyUsage

        if (
            keyUsage != null
        ) {

            val keyCertSignIndex =
                CertificateChainValidationConstants
                    .KEY_USAGE_KEY_CERT_SIGN

            if (
                keyUsage.size <=
                keyCertSignIndex ||
                !keyUsage[keyCertSignIndex]
            ) {

                return CertificateChainValidationResult
                    .InvalidRootCertificate(
                        "Root certificate does not permit certificate signing."
                    )
            }
        }

        return CertificateChainValidationResult.Valid
    }

    /**
     * Determines whether the last certificate is self-signed.
     */
    fun isSelfSigned(
        certificate: X509Certificate
    ): Boolean {

        return try {

            certificate.verify(
                certificate.publicKey
            )

            certificate.subjectX500Principal ==
                    certificate.issuerX500Principal

        } catch (
            _: Exception
        ) {

            false
        }
    }

    // =========================================================================
    // Leaf Certificate Validation
    // =========================================================================

    /**
     * Validates the leaf certificate.
     */
    fun validateLeafCertificate(
        certificate: X509Certificate,
        policy: CertificateChainValidationPolicy =
            CertificateChainValidationPolicy.default()
    ): CertificateChainValidationResult {

        if (
            certificate.basicConstraints >= 0
        ) {

            return CertificateChainValidationResult
                .InvalidLeafCertificate(
                    "Leaf certificate must be an end-entity certificate."
                )
        }

        val result =
            certificateValidator.validate(
                certificate =
                    certificate,
                policy =
                    policy.certificatePolicy
            )

        return if (
            result is
            CertificateValidationResult.Valid
        ) {

            CertificateChainValidationResult.Valid

        } else {

            CertificateChainValidationResult
                .CertificateValidationFailed(
                    index = 0,
                    reason =
                        result.toString()
                )
        }
    }

    /**
     * Validates a TLS server leaf certificate for a hostname.
     */
    fun validateTlsServerLeaf(
        certificate: X509Certificate,
        hostname: String,
        policy: CertificateChainValidationPolicy =
            CertificateChainValidationPolicy.tlsServer()
    ): CertificateChainValidationResult {

        val result =
            certificateValidator
                .validateServerCertificate(
                    certificate =
                        certificate,
                    hostname =
                        hostname,
                    policy =
                        policy.certificatePolicy
                )

        return if (
            result is
            CertificateValidationResult.Valid
        ) {

            CertificateChainValidationResult.Valid

        } else {

            CertificateChainValidationResult
                .CertificateValidationFailed(
                    index = 0,
                    reason =
                        result.toString()
                )
        }
    }

    // =========================================================================
    // Chain Information
    // =========================================================================

    /**
     * Returns the leaf certificate.
     */
    fun getLeaf(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.firstOrNull()
    }

    /**
     * Returns the root certificate.
     */
    fun getRoot(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.lastOrNull()
    }

    /**
     * Returns intermediate certificates.
     */
    fun getIntermediates(
        certificateChain: List<X509Certificate>
    ): List<X509Certificate> {

        if (
            certificateChain.size <= 2
        ) {

            return emptyList()
        }

        return certificateChain.subList(
            1,
            certificateChain.lastIndex
        )
    }

    /**
     * Returns chain length.
     */
    fun getChainLength(
        certificateChain: List<X509Certificate>
    ): Int {

        return certificateChain.size
    }

    /**
     * Returns SHA-256 fingerprints for all certificates in the chain.
     */
    fun getChainFingerprints(
        certificateChain: List<X509Certificate>
    ): List<String> {

        return certificateChain.map {
            certificateManager
                .getSha256Fingerprint(
                    it
                )
        }
    }

    // =========================================================================
    // Security Assessment
    // =========================================================================

    /**
     * Produces a complete chain security assessment.
     */
    fun assess(
        certificateChain: List<X509Certificate>,
        policy: CertificateChainValidationPolicy =
            CertificateChainValidationPolicy.default()
    ): CertificateChainSecurityAssessment {

        val checks =
            mutableListOf<
                    CertificateChainValidationResult
                    >()

        checks +=
            validateStructure(
                certificateChain
            )

        checks +=
            validateCertificateValidity(
                certificateChain
            )

        checks +=
            validateIssuerRelationships(
                certificateChain
            )

        checks +=
            validateCaConstraints(
                certificateChain
            )

        checks +=
            validatePathLengthConstraints(
                certificateChain
            )

        checks +=
            validateCertificatesAgainstPolicy(
                certificateChain,
                policy
            )

        if (
            policy.requireSystemTrust
        ) {

            checks +=
                validateAgainstSystemTrustStore(
                    certificateChain
                )
        }

        val blockingIssues =
            checks.filter {
                it !is
                        CertificateChainValidationResult.Valid &&
                        it.isBlocking
            }

        val warnings =
            checks.filter {
                it !is
                        CertificateChainValidationResult.Valid &&
                        !it.isBlocking
            }

        return CertificateChainSecurityAssessment(
            secure =
                blockingIssues.isEmpty(),

            chainLength =
                certificateChain.size,

            blockingIssues =
                blockingIssues,

            warnings =
                warnings,

            fingerprints =
                getChainFingerprints(
                    certificateChain
                )
        )
    }
}

/**
 * Validation policy for certificate chains.
 */
data class CertificateChainValidationPolicy(
    val maxChainLength: Int,

    val requireSystemTrust: Boolean,

    val certificatePolicy:
        CertificateValidationPolicy
) {

    companion object {

        /**
         * Default SentriX chain policy.
         */
        fun default():
                CertificateChainValidationPolicy {

            return CertificateChainValidationPolicy(

                maxChainLength =
                    CertificateChainValidationConstants
                        .DEFAULT_MAX_CHAIN_LENGTH,

                requireSystemTrust =
                    true,

                certificatePolicy =
                    CertificateValidationPolicy
                        .default()
            )
        }

        /**
         * TLS server certificate-chain policy.
         */
        fun tlsServer():
                CertificateChainValidationPolicy {

            return CertificateChainValidationPolicy(

                maxChainLength =
                    CertificateChainValidationConstants
                        .DEFAULT_MAX_CHAIN_LENGTH,

                requireSystemTrust =
                    true,

                certificatePolicy =
                    CertificateValidationPolicy
                        .tlsServer()
            )
        }

        /**
         * Strict high-security certificate-chain policy.
         */
        fun highSecurity():
                CertificateChainValidationPolicy {

            return CertificateChainValidationPolicy(

                maxChainLength =
                    CertificateChainValidationConstants
                        .STRICT_MAX_CHAIN_LENGTH,

                requireSystemTrust =
                    true,

                certificatePolicy =
                    CertificateValidationPolicy
                        .highSecurity()
            )
        }
    }
}

/**
 * Result returned by certificate-chain validation.
 */
sealed class CertificateChainValidationResult {

    /**
     * Complete validation succeeded.
     */
    data object Valid :
        CertificateChainValidationResult()

    /**
     * No certificates were supplied.
     */
    data object EmptyChain :
        CertificateChainValidationResult()

    /**
     * Chain contains more certificates than permitted.
     */
    data class ChainTooLong(
        val actualLength: Int,
        val maximumLength: Int
    ) : CertificateChainValidationResult()

    /**
     * Duplicate certificate detected.
     */
    data object DuplicateCertificates :
        CertificateChainValidationResult()

    /**
     * Leaf certificate is invalid.
     */
    data class InvalidLeafCertificate(
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * A non-leaf certificate does not satisfy CA requirements.
     */
    data class InvalidCertificateAuthority(
        val index: Int,
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * Certificate in chain is expired.
     */
    data class ExpiredCertificate(
        val index: Int,
        val expirationDate: Date
    ) : CertificateChainValidationResult()

    /**
     * Certificate in chain is not yet valid.
     */
    data class NotYetValidCertificate(
        val index: Int,
        val validFrom: Date
    ) : CertificateChainValidationResult()

    /**
     * Individual certificate validation failed.
     */
    data class CertificateValidationFailed(
        val index: Int,
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * Issuer DN does not match the expected issuer.
     */
    data class IssuerMismatch(
        val certificateIndex: Int,
        val issuerIndex: Int
    ) : CertificateChainValidationResult()

    /**
     * Certificate signature could not be verified using its issuer.
     */
    data class SignatureVerificationFailed(
        val certificateIndex: Int,
        val issuerIndex: Int
    ) : CertificateChainValidationResult()

    /**
     * Path length constraint was exceeded.
     */
    data class PathLengthConstraintExceeded(
        val certificateIndex: Int,
        val maximum: Int,
        val actual: Int
    ) : CertificateChainValidationResult()

    /**
     * Root certificate is invalid.
     */
    data class InvalidRootCertificate(
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * Certificate is not trusted by the system trust store.
     */
    data class TrustValidationFailed(
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * System trust store is unavailable.
     */
    data object TrustStoreUnavailable :
        CertificateChainValidationResult()

    /**
     * Validation policy itself is invalid.
     */
    data class InvalidPolicy(
        val reason: String
    ) : CertificateChainValidationResult()

    /**
     * Unexpected validation error.
     */
    data class Error(
        val cause: Throwable
    ) : CertificateChainValidationResult()

    /**
     * Unknown validation result.
     */
    data object Unknown :
        CertificateChainValidationResult()

    /**
     * Determines whether the result should block a protected
     * security operation.
     */
    val isBlocking: Boolean
        get() = when (this) {

            Valid ->
                false

            EmptyChain ->
                true

            is ChainTooLong ->
                true

            DuplicateCertificates ->
                true

            is InvalidLeafCertificate ->
                true

            is InvalidCertificateAuthority ->
                true

            is ExpiredCertificate ->
                true

            is NotYetValidCertificate ->
                true

            is CertificateValidationFailed ->
                true

            is IssuerMismatch ->
                true

            is SignatureVerificationFailed ->
                true

            is PathLengthConstraintExceeded ->
                true

            is InvalidRootCertificate ->
                true

            is TrustValidationFailed ->
                true

            TrustStoreUnavailable ->
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
 * High-level security assessment for a certificate chain.
 */
data class CertificateChainSecurityAssessment(
    val secure: Boolean,
    val chainLength: Int,
    val blockingIssues:
        List<CertificateChainValidationResult>,
    val warnings:
        List<CertificateChainValidationResult>,
    val fingerprints: List<String>
)

/**
 * Internal constants for chain validation.
 */
private object CertificateChainValidationConstants {

    const val X509_TYPE =
        "X.509"

    const val PKIX =
        "PKIX"

    const val ANDROID_TRUST_STORE =
        "AndroidCAStore"

    // -------------------------------------------------------------------------
    // Chain Limits
    // -------------------------------------------------------------------------

    const val MIN_CHAIN_LENGTH =
        1

    const val DEFAULT_MAX_CHAIN_LENGTH =
        10

    const val STRICT_MAX_CHAIN_LENGTH =
        6

    const val ABSOLUTE_MAX_CHAIN_LENGTH =
        20

    // -------------------------------------------------------------------------
    // X.509 Key Usage
    // -------------------------------------------------------------------------

    /**
     * KeyUsage.keyCertSign index.
     *
     * X.509 KeyUsage:
     *
     * 0 - digitalSignature
     * 1 - nonRepudiation/contentCommitment
     * 2 - keyEncipherment
     * 3 - dataEncipherment
     * 4 - keyAgreement
     * 5 - keyCertSign
     * 6 - cRLSign
     */
    const val KEY_USAGE_KEY_CERT_SIGN =
        5
}
