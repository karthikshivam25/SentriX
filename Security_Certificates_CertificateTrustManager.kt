package com.sentrix.security.certificates

import android.content.Context
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * SentriX Certificate Trust Manager
 *
 * Central trust-decision component for the certificate security subsystem.
 *
 * Responsibilities:
 *
 * - Evaluate whether a certificate should be trusted.
 * - Evaluate whether a certificate chain should be trusted.
 * - Use Android's system trust store.
 * - Coordinate CertificateValidator.
 * - Coordinate CertificateChainValidator.
 * - Support explicit application trust policies.
 * - Detect explicitly blocked certificates.
 * - Detect explicitly trusted certificate fingerprints.
 * - Produce auditable trust decisions.
 *
 * This class DOES NOT:
 *
 * - Disable TLS certificate verification.
 * - Accept arbitrary/self-signed certificates automatically.
 * - Modify Android's system trust store.
 * - Store private keys.
 * - Perform SSL pinning.
 * - Replace the Android TLS trust implementation.
 *
 * SSL pinning remains a separate security concern and belongs in:
 *
 *      com.sentrix.security.sslpinning
 *
 * Architecture:
 *
 *      Certificate
 *          │
 *          ▼
 *      CertificateTrustManager
 *          │
 *      ┌───┼───────────────┐
 *      ▼   ▼               ▼
 * Validator ChainValidator TrustStore
 *      │   │               │
 *      └───┼───────────────┘
 *          ▼
 *      TrustDecision
 */
class CertificateTrustManager(
    context: Context,
    private val certificateManager: CertificateManager =
        CertificateManager(context),
    private val certificateValidator: CertificateValidator =
        CertificateValidator(
            context = context,
            certificateManager = certificateManager
        ),
    private val certificateChainValidator:
        CertificateChainValidator =
            CertificateChainValidator(
                context = context,
                certificateManager =
                    certificateManager,
                certificateValidator =
                    certificateValidator
            )
) {

    private val applicationContext =
        context.applicationContext

    // =========================================================================
    // Main Trust Evaluation
    // =========================================================================

    /**
     * Evaluates whether an individual certificate is trusted using
     * the default SentriX trust policy.
     */
    fun evaluate(
        certificate: X509Certificate
    ): CertificateTrustDecision {

        return evaluate(
            certificate = certificate,
            policy =
                CertificateTrustPolicy.default()
        )
    }

    /**
     * Evaluates an individual certificate against a supplied trust policy.
     */
    fun evaluate(
        certificate: X509Certificate,
        policy: CertificateTrustPolicy
    ): CertificateTrustDecision {

        val policyResult =
            validateTrustPolicy(
                policy
            )

        if (
            policyResult !is
            CertificateTrustPolicyValidation.Valid
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .PolicyError,
                reason =
                    policyResult.reason,
                certificateFingerprint =
                    safeFingerprint(
                        certificate
                    )
            )
        }

        val fingerprint =
            safeFingerprint(
                certificate
            )

        // ---------------------------------------------------------------------
        // Explicit block list takes precedence.
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.blockedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyBlocked,
                reason =
                    "Certificate fingerprint is explicitly blocked.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Certificate validation.
        // ---------------------------------------------------------------------

        val validationResult =
            certificateValidator.validate(
                certificate = certificate,
                policy =
                    policy.certificatePolicy
            )

        if (
            validationResult !is
            CertificateValidationResult.Valid
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .CertificateInvalid,
                reason =
                    describeValidationResult(
                        validationResult
                    ),
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Explicit application trust.
        //
        // Explicit trust does not override invalid certificate properties.
        // The certificate has already passed validation above.
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.trustedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyTrusted,
                reason =
                    "Certificate matches an explicitly trusted SHA-256 fingerprint.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Android system trust store.
        // ---------------------------------------------------------------------

        if (
            policy.requireSystemTrust
        ) {

            val systemTrusted =
                isTrustedBySystemStore(
                    certificate
                )

            if (
                systemTrusted
            ) {

                return CertificateTrustDecision(
                    status =
                        CertificateTrustStatus
                            .SystemTrusted,
                    reason =
                        "Certificate is present in the Android system trust store.",
                    certificateFingerprint =
                        fingerprint
                )
            }

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .Untrusted,
                reason =
                    "Certificate is not explicitly trusted and is not " +
                            "present in the Android system trust store.",
                certificateFingerprint =
                    fingerprint
            )
        }

        return CertificateTrustDecision(
            status =
                CertificateTrustStatus
                    .ValidationPassed,
            reason =
                "Certificate passed SentriX validation but system trust " +
                        "was not required by policy.",
            certificateFingerprint =
                fingerprint
        )
    }

    // =========================================================================
    // Chain Trust Evaluation
    // =========================================================================

    /**
     * Evaluates a complete certificate chain.
     *
     * Expected order:
     *
     *      Leaf -> Intermediate -> Root
     */
    fun evaluateChain(
        certificateChain: List<X509Certificate>
    ): CertificateTrustDecision {

        return evaluateChain(
            certificateChain = certificateChain,
            policy =
                CertificateTrustPolicy.default()
        )
    }

    /**
     * Evaluates a certificate chain against the supplied trust policy.
     */
    fun evaluateChain(
        certificateChain: List<X509Certificate>,
        policy: CertificateTrustPolicy
    ): CertificateTrustDecision {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .InvalidChain,
                reason =
                    "Certificate chain is empty.",
                certificateFingerprint =
                    null
            )
        }

        val leaf =
            certificateChain.first()

        val fingerprint =
            safeFingerprint(
                leaf
            )

        // ---------------------------------------------------------------------
        // Explicitly blocked leaf.
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.blockedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyBlocked,
                reason =
                    "Leaf certificate fingerprint is explicitly blocked.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Chain validation.
        // ---------------------------------------------------------------------

        val chainResult =
            certificateChainValidator.validate(
                certificateChain = certificateChain,
                policy =
                    CertificateChainValidationPolicy(
                        maxChainLength =
                            policy.maxChainLength,
                        requireSystemTrust =
                            false,
                        certificatePolicy =
                            policy.certificatePolicy
                    )
            )

        if (
            chainResult !is
            CertificateChainValidationResult.Valid
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .InvalidChain,
                reason =
                    describeChainResult(
                        chainResult
                    ),
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Explicitly trusted leaf.
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.trustedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyTrusted,
                reason =
                    "Leaf certificate matches an explicitly trusted " +
                            "SHA-256 fingerprint.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // System trust.
        // ---------------------------------------------------------------------

        if (
            policy.requireSystemTrust
        ) {

            val systemTrustResult =
                certificateChainValidator
                    .validateAgainstSystemTrustStore(
                        certificateChain
                    )

            if (
                systemTrustResult !is
                CertificateChainValidationResult.Valid
            ) {

                return CertificateTrustDecision(
                    status =
                        CertificateTrustStatus
                            .Untrusted,
                    reason =
                        describeChainResult(
                            systemTrustResult
                        ),
                    certificateFingerprint =
                        fingerprint
                )
            }

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .SystemTrusted,
                reason =
                    "Certificate chain successfully validated against " +
                            "the Android system trust store.",
                certificateFingerprint =
                    fingerprint
            )
        }

        return CertificateTrustDecision(
            status =
                CertificateTrustStatus
                    .ValidationPassed,
            reason =
                "Certificate chain passed SentriX validation.",
            certificateFingerprint =
                fingerprint
        )
    }

    // =========================================================================
    // System Trust Store
    // =========================================================================

    /**
     * Determines whether an individual certificate is present in the
     * Android system CA store.
     *
     * This is a certificate identity check. It is not equivalent to
     * complete PKIX path validation.
     */
    fun isTrustedBySystemStore(
        certificate: X509Certificate
    ): Boolean {

        val targetFingerprint =
            safeFingerprint(
                certificate
            )
                ?: return false

        val trustStore =
            try {

                KeyStore.getInstance(
                    CertificateTrustConstants
                        .ANDROID_TRUST_STORE
                ).apply {

                    load(null)
                }

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
                trustStore.getCertificate(
                    alias
                ) as? X509Certificate
                    ?: continue

            val fingerprint =
                safeFingerprint(
                    trustedCertificate
                )
                    ?: continue

            if (
                fingerprint == targetFingerprint
            ) {

                return true
            }
        }

        return false
    }

    /**
     * Returns all SHA-256 fingerprints of certificates currently
     * available in the Android system trust store.
     *
     * This is intended for diagnostics and security inventory.
     */
    fun getSystemTrustedFingerprints():
            Set<String> {

        val trustStore =
            try {

                KeyStore.getInstance(
                    CertificateTrustConstants
                        .ANDROID_TRUST_STORE
                ).apply {

                    load(null)
                }

            } catch (
                _: Exception
            ) {

                return emptySet()
            }

        val fingerprints =
            mutableSetOf<String>()

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

            val fingerprint =
                safeFingerprint(
                    certificate
                )
                    ?: continue

            fingerprints += fingerprint
        }

        return fingerprints
    }

    // =========================================================================
    // Explicit Trust
    // =========================================================================

    /**
     * Checks whether a certificate matches an explicitly trusted
     * fingerprint.
     */
    fun isExplicitlyTrusted(
        certificate: X509Certificate,
        trustedFingerprints: Set<String>
    ): Boolean {

        val fingerprint =
            safeFingerprint(
                certificate
            )
                ?: return false

        return containsFingerprint(
            fingerprint,
            trustedFingerprints
        )
    }

    /**
     * Checks whether a certificate is explicitly blocked.
     */
    fun isExplicitlyBlocked(
        certificate: X509Certificate,
        blockedFingerprints: Set<String>
    ): Boolean {

        val fingerprint =
            safeFingerprint(
                certificate
            )
                ?: return false

        return containsFingerprint(
            fingerprint,
            blockedFingerprints
        )
    }

    /**
     * Checks explicit trust first, followed by explicit block.
     *
     * Block always wins.
     */
    fun evaluateExplicitTrust(
        certificate: X509Certificate,
        trustedFingerprints: Set<String>,
        blockedFingerprints: Set<String>
    ): CertificateTrustDecision {

        val fingerprint =
            safeFingerprint(
                certificate
            )

        if (
            fingerprint == null
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .EvaluationError,
                reason =
                    "Unable to calculate certificate fingerprint.",
                certificateFingerprint =
                    null
            )
        }

        if (
            containsFingerprint(
                fingerprint,
                blockedFingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyBlocked,
                reason =
                    "Certificate is explicitly blocked.",
                certificateFingerprint =
                    fingerprint
            )
        }

        if (
            containsFingerprint(
                fingerprint,
                trustedFingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyTrusted,
                reason =
                    "Certificate is explicitly trusted.",
                certificateFingerprint =
                    fingerprint
            )
        }

        return CertificateTrustDecision(
            status =
                CertificateTrustStatus
                    .NoExplicitDecision,
            reason =
                "Certificate has no explicit trust or block decision.",
            certificateFingerprint =
                fingerprint
        )
    }

    // =========================================================================
    // Hostname Trust
    // =========================================================================

    /**
     * Evaluates trust for a TLS server certificate and hostname.
     *
     * The hostname must match the certificate SAN before the certificate
     * can be trusted for the requested server identity.
     */
    fun evaluateServerCertificate(
        certificate: X509Certificate,
        hostname: String
    ): CertificateTrustDecision {

        return evaluateServerCertificate(
            certificate = certificate,
            hostname = hostname,
            policy =
                CertificateTrustPolicy.tlsServer()
        )
    }

    /**
     * Evaluates a TLS server certificate against a custom policy.
     */
    fun evaluateServerCertificate(
        certificate: X509Certificate,
        hostname: String,
        policy: CertificateTrustPolicy
    ): CertificateTrustDecision {

        val fingerprint =
            safeFingerprint(
                certificate
            )

        // ---------------------------------------------------------------------
        // Explicit block
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.blockedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyBlocked,
                reason =
                    "Server certificate is explicitly blocked.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Certificate validation + hostname validation
        // ---------------------------------------------------------------------

        val validation =
            certificateValidator
                .validateServerCertificate(
                    certificate =
                        certificate,
                    hostname =
                        hostname,
                    policy =
                        policy.certificatePolicy
                )

        if (
            validation !is
            CertificateValidationResult.Valid
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .CertificateInvalid,
                reason =
                    describeValidationResult(
                        validation
                    ),
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // Explicit trust
        // ---------------------------------------------------------------------

        if (
            fingerprint != null &&
            containsFingerprint(
                fingerprint,
                policy.trustedSha256Fingerprints
            )
        ) {

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .ExplicitlyTrusted,
                reason =
                    "Server certificate matches an explicitly trusted " +
                            "SHA-256 fingerprint.",
                certificateFingerprint =
                    fingerprint
            )
        }

        // ---------------------------------------------------------------------
        // System trust
        // ---------------------------------------------------------------------

        if (
            policy.requireSystemTrust
        ) {

            if (
                !isTrustedBySystemStore(
                    certificate
                )
            ) {

                return CertificateTrustDecision(
                    status =
                        CertificateTrustStatus
                            .Untrusted,
                    reason =
                        "Server certificate is not trusted by the " +
                                "Android system trust store.",
                    certificateFingerprint =
                        fingerprint
                )
            }

            return CertificateTrustDecision(
                status =
                    CertificateTrustStatus
                        .SystemTrusted,
                reason =
                    "Server certificate passed certificate, hostname, " +
                            "and system trust checks.",
                certificateFingerprint =
                    fingerprint
            )
        }

        return CertificateTrustDecision(
            status =
                CertificateTrustStatus
                    .ValidationPassed,
            reason =
                "Server certificate passed SentriX validation.",
            certificateFingerprint =
                fingerprint
        )
    }

    // =========================================================================
    // Chain Trust Helpers
    // =========================================================================

    /**
     * Determines whether a chain has a trusted root.
     */
    fun hasTrustedRoot(
        certificateChain: List<X509Certificate>
    ): Boolean {

        if (
            certificateChain.isEmpty()
        ) {

            return false
        }

        val root =
            certificateChain.last()

        return isTrustedBySystemStore(
            root
        )
    }

    /**
     * Returns the root certificate from a chain.
     */
    fun getRootCertificate(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.lastOrNull()
    }

    /**
     * Returns the leaf certificate from a chain.
     */
    fun getLeafCertificate(
        certificateChain: List<X509Certificate>
    ): X509Certificate? {

        return certificateChain.firstOrNull()
    }

    /**
     * Determines whether the supplied chain has a valid structure.
     */
    fun hasValidStructure(
        certificateChain: List<X509Certificate>
    ): Boolean {

        return certificateChainValidator
            .validateStructure(
                certificateChain
            ) is
                CertificateChainValidationResult.Valid
    }

    /**
     * Determines whether the supplied chain is trusted by the
     * Android system trust infrastructure.
     */
    fun isSystemTrustedChain(
        certificateChain: List<X509Certificate>
    ): Boolean {

        return certificateChainValidator
            .validateAgainstSystemTrustStore(
                certificateChain
            ) is
                CertificateChainValidationResult.Valid
    }

    // =========================================================================
    // Trust State
    // =========================================================================

    /**
     * Returns whether a trust decision allows a protected operation
     * to continue.
     */
    fun isTrusted(
        decision: CertificateTrustDecision
    ): Boolean {

        return when (
            decision.status
        ) {

            CertificateTrustStatus.SystemTrusted,
            CertificateTrustStatus.ExplicitlyTrusted,
            CertificateTrustStatus.ValidationPassed -> true

            CertificateTrustStatus.ExplicitlyBlocked,
            CertificateTrustStatus.CertificateInvalid,
            CertificateTrustStatus.InvalidChain,
            CertificateTrustStatus.Untrusted,
            CertificateTrustStatus.PolicyError,
            CertificateTrustStatus.EvaluationError -> false

            CertificateTrustStatus.NoExplicitDecision -> false
        }
    }

    /**
     * Determines whether a decision should block a network operation.
     */
    fun shouldBlock(
        decision: CertificateTrustDecision
    ): Boolean {

        return !isTrusted(
            decision
        )
    }

    /**
     * Determines whether the decision was based on an explicit
     * application trust rule.
     */
    fun isExplicitDecision(
        decision: CertificateTrustDecision
    ): Boolean {

        return decision.status ==
                CertificateTrustStatus
                    .ExplicitlyTrusted ||
                decision.status ==
                CertificateTrustStatus
                    .ExplicitlyBlocked
    }

    /**
     * Determines whether the certificate was trusted by the
     * Android platform trust store.
     */
    fun isSystemTrustDecision(
        decision: CertificateTrustDecision
    ): Boolean {

        return decision.status ==
                CertificateTrustStatus
                    .SystemTrusted
    }

    // =========================================================================
    // Security Assessment
    // =========================================================================

    /**
     * Produces a security assessment for a certificate.
     */
    fun assess(
        certificate: X509Certificate,
        policy: CertificateTrustPolicy =
            CertificateTrustPolicy.default()
    ): CertificateTrustAssessment {

        val decision =
            evaluate(
                certificate = certificate,
                policy = policy
            )

        return CertificateTrustAssessment(
            trusted =
                isTrusted(
                    decision
                ),
            status =
                decision.status,
            reason =
                decision.reason,
            fingerprint =
                decision.certificateFingerprint
        )
    }

    /**
     * Produces a security assessment for a certificate chain.
     */
    fun assessChain(
        certificateChain: List<X509Certificate>,
        policy: CertificateTrustPolicy =
            CertificateTrustPolicy.default()
    ): CertificateTrustAssessment {

        val decision =
            evaluateChain(
                certificateChain = certificateChain,
                policy = policy
            )

        return CertificateTrustAssessment(
            trusted =
                isTrusted(
                    decision
                ),
            status =
                decision.status,
            reason =
                decision.reason,
            fingerprint =
                decision.certificateFingerprint
        )
    }

    // =========================================================================
    // Fingerprint Utilities
    // =========================================================================

    /**
     * Safely obtains the SHA-256 fingerprint of a certificate.
     */
    private fun safeFingerprint(
        certificate: X509Certificate
    ): String? {

        return try {

            certificateManager
                .getSha256Fingerprint(
                    certificate
                )

        } catch (
            _: Exception
        ) {

            null
        }
    }

    /**
     * Performs normalized fingerprint comparison.
     */
    private fun containsFingerprint(
        actualFingerprint: String,
        fingerprints: Collection<String>
    ): Boolean {

        val normalizedActual =
            normalizeFingerprint(
                actualFingerprint
            )

        return fingerprints.any {
            normalizeFingerprint(
                it
            ) == normalizedActual
        }
    }

    /**
     * Normalizes fingerprint formatting.
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
    // Error Description
    // =========================================================================

    /**
     * Converts a certificate validation result into a safe description.
     */
    private fun describeValidationResult(
        result: CertificateValidationResult
    ): String {

        return when (result) {

            CertificateValidationResult.Valid ->
                "Certificate validation succeeded."

            is CertificateValidationResult.Expired ->
                "Certificate has expired."

            is CertificateValidationResult.NotYetValid ->
                "Certificate is not yet valid."

            is CertificateValidationResult.ExpiringSoon ->
                "Certificate is approaching expiration."

            is CertificateValidationResult.WeakPublicKey ->
                "Certificate public key does not satisfy security policy."

            is CertificateValidationResult.InvalidPublicKey ->
                "Certificate public key is invalid."

            is CertificateValidationResult.UnsupportedPublicKey ->
                "Certificate public-key algorithm is unsupported."

            is CertificateValidationResult.DisallowedSignatureAlgorithm ->
                "Certificate signature algorithm is disallowed."

            is CertificateValidationResult.UnsupportedSignatureAlgorithm ->
                "Certificate signature algorithm is unsupported."

            CertificateValidationResult.MissingKeyUsage ->
                "Required certificate key usage is missing."

            is CertificateValidationResult.InvalidKeyUsage ->
                "Certificate key usage is invalid."

            CertificateValidationResult.MissingExtendedKeyUsage ->
                "Required extended key usage is missing."

            is CertificateValidationResult.InvalidExtendedKeyUsage ->
                "Certificate extended key usage is invalid."

            is CertificateValidationResult.HostnameMismatch ->
                "Certificate hostname does not match."

            is CertificateValidationResult.InvalidFingerprint ->
                "Certificate fingerprint is invalid."

            CertificateValidationResult.FingerprintMismatch ->
                "Certificate fingerprint does not match."

            is CertificateValidationResult.InvalidChain ->
                "Certificate chain is invalid."

            is CertificateValidationResult.UntrustedCertificate ->
                "Certificate is not trusted."

            CertificateValidationResult.TrustStoreUnavailable ->
                "System trust store is unavailable."

            is CertificateValidationResult.InvalidIssuer ->
                "Certificate issuer validation failed."

            is CertificateValidationResult.UnexpectedCertificateType ->
                "Unexpected certificate type."

            is CertificateValidationResult.InvalidHostname ->
                "Certificate hostname is invalid."

            is CertificateValidationResult.InvalidPolicy ->
                "Certificate validation policy is invalid."

            is CertificateValidationResult.Error ->
                "Certificate validation encountered an error."

            CertificateValidationResult.Unknown ->
                "Certificate validation produced an unknown result."
        }
    }

    /**
     * Converts a certificate-chain validation result into a safe
     * trust-decision description.
     */
    private fun describeChainResult(
        result: CertificateChainValidationResult
    ): String {

        return when (result) {

            CertificateChainValidationResult.Valid ->
                "Certificate chain validation succeeded."

            CertificateChainValidationResult.EmptyChain ->
                "Certificate chain is empty."

            is CertificateChainValidationResult.ChainTooLong ->
                "Certificate chain exceeds the permitted length."

            CertificateChainValidationResult.DuplicateCertificates ->
                "Certificate chain contains duplicate certificates."

            is CertificateChainValidationResult.InvalidLeafCertificate ->
                "Leaf certificate is invalid."

            is CertificateChainValidationResult.InvalidCertificateAuthority ->
                "Certificate authority validation failed."

            is CertificateChainValidationResult.ExpiredCertificate ->
                "A certificate in the chain has expired."

            is CertificateChainValidationResult.NotYetValidCertificate ->
                "A certificate in the chain is not yet valid."

            is CertificateChainValidationResult.CertificateValidationFailed ->
                "Certificate validation failed within the chain."

            is CertificateChainValidationResult.IssuerMismatch ->
                "Certificate issuer relationship is invalid."

            is CertificateChainValidationResult.SignatureVerificationFailed ->
                "Certificate signature verification failed."

            is CertificateChainValidationResult.PathLengthConstraintExceeded ->
                "Certificate path length constraint was exceeded."

            is CertificateChainValidationResult.InvalidRootCertificate ->
                "Root certificate is invalid."

            is CertificateChainValidationResult.TrustValidationFailed ->
                "System trust validation failed."

            CertificateChainValidationResult.TrustStoreUnavailable ->
                "System trust store is unavailable."

            is CertificateChainValidationResult.InvalidPolicy ->
                "Certificate-chain policy is invalid."

            is CertificateChainValidationResult.Error ->
                "Certificate-chain validation encountered an error."

            CertificateChainValidationResult.Unknown ->
                "Certificate-chain validation produced an unknown result."
        }
    }

    // =========================================================================
    // Policy Validation
    // =========================================================================

    /**
     * Validates the trust-policy structure.
     */
    private fun validateTrustPolicy(
        policy: CertificateTrustPolicy
    ): CertificateTrustPolicyValidation {

        if (
            policy.maxChainLength <
            CertificateTrustConstants.MIN_CHAIN_LENGTH
        ) {

            return CertificateTrustPolicyValidation.Invalid(
                "Maximum chain length is invalid."
            )
        }

        if (
            policy.maxChainLength >
            CertificateTrustConstants
                .ABSOLUTE_MAX_CHAIN_LENGTH
        ) {

            return CertificateTrustPolicyValidation.Invalid(
                "Maximum chain length exceeds the SentriX limit."
            )
        }

        return CertificateTrustPolicyValidation.Valid
    }
}

/**
 * SentriX certificate trust policy.
 *
 * Trust is deliberately deny-by-default when system trust or explicit
 * trust has not been established.
 */
data class CertificateTrustPolicy(

    /**
     * Whether Android's system trust store must validate the certificate.
     */
    val requireSystemTrust: Boolean,

    /**
     * Maximum permitted certificate-chain length.
     */
    val maxChainLength: Int,

    /**
     * SHA-256 fingerprints explicitly trusted by the application.
     */
    val trustedSha256Fingerprints: Set<String>,

    /**
     * SHA-256 fingerprints explicitly blocked by the application.
     *
     * Blocked certificates always take precedence over trusted entries.
     */
    val blockedSha256Fingerprints: Set<String>,

    /**
     * Individual certificate validation policy.
     */
    val certificatePolicy:
        CertificateValidationPolicy
) {

    companion object {

        /**
         * Default SentriX trust policy.
         *
         * Trust is based on successful certificate validation plus
         * Android system trust.
         */
        fun default():
                CertificateTrustPolicy {

            return CertificateTrustPolicy(

                requireSystemTrust =
                    true,

                maxChainLength =
                    CertificateTrustConstants
                        .DEFAULT_MAX_CHAIN_LENGTH,

                trustedSha256Fingerprints =
                    emptySet(),

                blockedSha256Fingerprints =
                    emptySet(),

                certificatePolicy =
                    CertificateValidationPolicy
                        .default()
            )
        }

        /**
         * TLS server trust policy.
         */
        fun tlsServer():
                CertificateTrustPolicy {

            return CertificateTrustPolicy(

                requireSystemTrust =
                    true,

                maxChainLength =
                    CertificateTrustConstants
                        .DEFAULT_MAX_CHAIN_LENGTH,

                trustedSha256Fingerprints =
                    emptySet(),

                blockedSha256Fingerprints =
                    emptySet(),

                certificatePolicy =
                    CertificateValidationPolicy
                        .tlsServer()
            )
        }

        /**
         * High-security trust policy.
         */
        fun highSecurity():
                CertificateTrustPolicy {

            return CertificateTrustPolicy(

                requireSystemTrust =
                    true,

                maxChainLength =
                    CertificateTrustConstants
                        .STRICT_MAX_CHAIN_LENGTH,

                trustedSha256Fingerprints =
                    emptySet(),

                blockedSha256Fingerprints =
                    emptySet(),

                certificatePolicy =
                    CertificateValidationPolicy
                        .highSecurity()
            )
        }

        /**
         * Creates a policy with explicit certificate trust entries.
         */
        fun withExplicitTrust(
            trustedFingerprints: Set<String>,
            blockedFingerprints: Set<String> =
                emptySet()
        ): CertificateTrustPolicy {

            return default().copy(
                trustedSha256Fingerprints =
                    trustedFingerprints,
                blockedSha256Fingerprints =
                    blockedFingerprints
            )
        }
    }
}

/**
 * Final trust decision produced by CertificateTrustManager.
 */
data class CertificateTrustDecision(

    /**
     * Final trust status.
     */
    val status: CertificateTrustStatus,

    /**
     * Safe explanation of the trust decision.
     */
    val reason: String,

    /**
     * SHA-256 fingerprint of the evaluated leaf/certificate.
     */
    val certificateFingerprint: String?
)

/**
 * Certificate trust states recognized by SentriX.
 */
enum class CertificateTrustStatus {

    /**
     * Certificate was validated and is trusted by Android's system
     * trust infrastructure.
     */
    SystemTrusted,

    /**
     * Certificate explicitly matches an application-approved
     * fingerprint.
     */
    ExplicitlyTrusted,

    /**
     * Certificate passed SentriX validation under a policy that does
     * not require system trust.
     */
    ValidationPassed,

    /**
     * Certificate was explicitly blocked.
     */
    ExplicitlyBlocked,

    /**
     * Certificate itself failed validation.
     */
    CertificateInvalid,

    /**
     * Certificate chain failed validation.
     */
    InvalidChain,

    /**
     * Certificate is not trusted.
     */
    Untrusted,

    /**
     * No explicit trust/block rule exists.
     */
    NoExplicitDecision,

    /**
     * Trust policy is invalid.
     */
    PolicyError,

    /**
     * Trust evaluation could not be completed.
     */
    EvaluationError
}

/**
 * High-level certificate trust assessment.
 */
data class CertificateTrustAssessment(

    /**
     * Whether the evaluated certificate/chain is trusted.
     */
    val trusted: Boolean,

    /**
     * Final trust state.
     */
    val status: CertificateTrustStatus,

    /**
     * Safe explanation.
     */
    val reason: String,

    /**
     * SHA-256 certificate fingerprint.
     */
    val fingerprint: String?
)

/**
 * Internal trust-policy validation result.
 */
private sealed class CertificateTrustPolicyValidation {

    data object Valid :
        CertificateTrustPolicyValidation()

    data class Invalid(
        val reason: String
    ) : CertificateTrustPolicyValidation()
}

/**
 * Internal constants for CertificateTrustManager.
 */
private object CertificateTrustConstants {

    /**
     * Android system CA trust store.
     */
    const val ANDROID_TRUST_STORE =
        "AndroidCAStore"

    /**
     * Minimum certificate-chain size.
     */
    const val MIN_CHAIN_LENGTH =
        1

    /**
     * Default maximum certificate-chain size.
     */
    const val DEFAULT_MAX_CHAIN_LENGTH =
        10

    /**
     * Strict maximum certificate-chain size.
     */
    const val STRICT_MAX_CHAIN_LENGTH =
        6

    /**
     * Absolute safety limit.
     */
    const val ABSOLUTE_MAX_CHAIN_LENGTH =
        20
}
