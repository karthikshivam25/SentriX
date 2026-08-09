package com.sentrix.security.certificates

import java.security.cert.X509Certificate

/**
 * SentriX Certificate Security Checker
 *
 * Enterprise-grade certificate security assessment component.
 *
 * This class acts as an orchestration layer over the certificate-security
 * components already implemented in the SentriX certificate subsystem.
 *
 * Responsibilities:
 *
 * - Perform comprehensive certificate security assessment.
 * - Combine expiration checks.
 * - Combine revocation checks.
 * - Combine fingerprint analysis.
 * - Optionally perform certificate pin validation.
 * - Produce a unified security result.
 * - Calculate an overall certificate risk level.
 * - Identify security violations.
 * - Provide actionable security recommendations.
 *
 * This class DOES NOT:
 *
 * - Implement cryptographic primitives itself.
 * - Replace CertificateValidator.
 * - Replace CertificateChainValidator.
 * - Replace CertificateTrustManager.
 * - Replace CertificatePinManager.
 * - Replace CertificateExpirationChecker.
 * - Replace CertificateRevocationChecker.
 * - Disable TLS validation.
 * - Automatically trust certificates.
 *
 * Architecture:
 *
 *       X509Certificate
 *              │
 *              ▼
 *     CertificateSecurityChecker
 *              │
 *       ┌──────┼──────────────┐
 *       ▼      ▼              ▼
 *   Expiration Revocation   Fingerprint
 *       │      │              │
 *       └──────┼──────────────┘
 *              ▼
 *       Trust / Pinning
 *              │
 *              ▼
 *      Security Assessment
 *              │
 *       ┌──────┼─────────┐
 *       ▼      ▼         ▼
 *      SAFE   WARNING   BLOCK
 */
class CertificateSecurityChecker(
    private val expirationChecker:
        CertificateExpirationChecker,

    private val revocationChecker:
        CertificateRevocationChecker,

    private val fingerprintManager:
        CertificateFingerprintManager,

    private val trustManager:
        CertificateTrustManager? = null,

    private val pinManager:
        CertificatePinManager? = null
) {

    // =========================================================================
    // Main Security Check
    // =========================================================================

    /**
     * Performs a comprehensive certificate security check.
     */
    fun check(
        certificate: X509Certificate
    ): CertificateSecurityResult {

        return check(
            certificate = certificate,
            configuration =
                CertificateSecurityConfiguration.default()
        )
    }

    /**
     * Performs a comprehensive certificate security assessment.
     */
    fun check(
        certificate: X509Certificate,
        configuration:
            CertificateSecurityConfiguration
    ): CertificateSecurityResult {

        val configurationError =
            validateConfiguration(
                configuration
            )

        if (
            configurationError != null
        ) {

            return CertificateSecurityResult
                .ConfigurationError(
                    configurationError
                )
        }

        // ---------------------------------------------------------------------
        // Fingerprint
        // ---------------------------------------------------------------------

        val fingerprint =
            try {

                fingerprintManager
                    .createFingerprint(
                        certificate
                    )

            } catch (
                exception: Exception
            ) {

                return CertificateSecurityResult
                    .FingerprintFailure(
                        exception
                    )
            }

        // ---------------------------------------------------------------------
        // Expiration
        // ---------------------------------------------------------------------

        val expirationResult =
            expirationChecker.check(
                certificate = certificate,
                configuration =
                    configuration
                        .expirationConfiguration
            )

        // ---------------------------------------------------------------------
        // Revocation
        // ---------------------------------------------------------------------

        val revocationResult =
            if (
                configuration.checkRevocation
            ) {

                revocationChecker.check(
                    certificate = certificate,
                    policy =
                        configuration
                            .revocationPolicy
                )

            } else {

                CertificateRevocationResult
                    .Unavailable(
                        reason =
                            "Revocation checking is disabled " +
                                    "by security policy."
                    )
            }

        // ---------------------------------------------------------------------
        // Trust
        // ---------------------------------------------------------------------

        val trustResult =
            if (
                configuration.checkTrust &&
                trustManager != null
            ) {

                performTrustCheck(
                    certificate
                )

            } else {

                CertificateTrustAssessment
                    .NotChecked(
                        reason =
                            if (
                                !configuration.checkTrust
                            ) {
                                "Trust checking disabled by policy."
                            } else {
                                "CertificateTrustManager is unavailable."
                            }
                    )
            }

        // ---------------------------------------------------------------------
        // Pinning
        // ---------------------------------------------------------------------

        val pinResult =
            if (
                configuration.checkPinning &&
                pinManager != null &&
                !configuration.hostname.isNullOrBlank()
            ) {

                pinManager.validate(
                    host =
                        configuration.hostname,
                    certificate =
                        certificate,
                    requirePinConfiguration =
                        configuration
                            .requirePinConfiguration
                )

            } else {

                CertificatePinAssessment
                    .NotChecked(
                        reason =
                            when {

                                !configuration.checkPinning ->
                                    "Certificate pinning disabled by policy."

                                pinManager == null ->
                                    "CertificatePinManager is unavailable."

                                configuration.hostname.isNullOrBlank() ->
                                    "Hostname was not supplied."

                                else ->
                                    "Pinning was not evaluated."
                            }
                    )
            }

        // ---------------------------------------------------------------------
        // Security Violations
        // ---------------------------------------------------------------------

        val violations =
            collectViolations(
                expiration =
                    expirationResult,
                revocation =
                    revocationResult,
                trust =
                    trustResult,
                pin =
                    pinResult,
                configuration =
                    configuration
            )

        // ---------------------------------------------------------------------
        // Overall Risk
        // ---------------------------------------------------------------------

        val risk =
            calculateRisk(
                expiration =
                    expirationResult,
                revocation =
                    revocationResult,
                trust =
                    trustResult,
                pin =
                    pinResult,
                violations =
                    violations
            )

        // ---------------------------------------------------------------------
        // Security Decision
        // ---------------------------------------------------------------------

        val decision =
            determineDecision(
                risk =
                    risk,
                violations =
                    violations,
                configuration =
                    configuration
            )

        // ---------------------------------------------------------------------
        // Recommendations
        // ---------------------------------------------------------------------

        val recommendations =
            generateRecommendations(
                expiration =
                    expirationResult,
                revocation =
                    revocationResult,
                trust =
                    trustResult,
                pin =
                    pinResult,
                risk =
                    risk
            )

        return CertificateSecurityResult
            .Evaluated(

                certificateFingerprint =
                    fingerprint,

                expiration =
                    expirationResult,

                revocation =
                    revocationResult,

                trust =
                    trustResult,

                pinning =
                    pinResult,

                risk =
                    risk,

                decision =
                    decision,

                violations =
                    violations,

                recommendations =
                    recommendations
            )
    }

    // =========================================================================
    // Chain Security Check
    // =========================================================================

    /**
     * Performs a security assessment over an entire certificate chain.
     */
    fun checkChain(
        certificateChain:
            List<X509Certificate>
    ): CertificateChainSecurityResult {

        return checkChain(
            certificateChain =
                certificateChain,
            configuration =
                CertificateSecurityConfiguration.default()
        )
    }

    /**
     * Performs a comprehensive chain security assessment.
     */
    fun checkChain(
        certificateChain:
            List<X509Certificate>,
        configuration:
            CertificateSecurityConfiguration
    ): CertificateChainSecurityResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainSecurityResult
                .EmptyChain
        }

        val individualResults =
            certificateChain.mapIndexed {
                index,
                certificate ->

                CertificateChainCertificateSecurity(
                    index =
                        index,
                    certificate =
                        certificate,
                    result =
                        check(
                            certificate,
                            configuration
                        )
                )
            }

        val expirationResult =
            expirationChecker.checkChain(
                certificateChain =
                    certificateChain,
                configuration =
                    configuration
                        .expirationConfiguration
            )

        val revocationResult =
            if (
                configuration.checkRevocation
            ) {

                revocationChecker.checkChain(
                    certificateChain =
                        certificateChain,
                    policy =
                        configuration
                            .revocationPolicy
                )

            } else {

                CertificateChainRevocationResult
                    .Unavailable(
                        reason =
                            "Revocation checking is disabled."
                    )
            }

        val violations =
            individualResults
                .flatMap {
                    it.result.violations
                }
                .distinct()

        val risk =
            calculateChainRisk(
                individualResults =
                    individualResults,
                expirationResult =
                    expirationResult,
                revocationResult =
                    revocationResult
            )

        val decision =
            if (
                risk == CertificateSecurityRisk.CRITICAL
            ) {

                CertificateSecurityDecision
                    .BLOCK

            } else if (
                risk == CertificateSecurityRisk.HIGH
            ) {

                if (
                    configuration
                        .blockHighRiskCertificates
                ) {

                    CertificateSecurityDecision
                        .BLOCK

                } else {

                    CertificateSecurityDecision
                        .WARN
                }

            } else if (
                risk == CertificateSecurityRisk.MEDIUM
            ) {

                CertificateSecurityDecision
                    .WARN

            } else {

                CertificateSecurityDecision
                    .ALLOW
            }

        return CertificateChainSecurityResult
            .Evaluated(

                certificates =
                    individualResults,

                expiration =
                    expirationResult,

                revocation =
                    revocationResult,

                risk =
                    risk,

                decision =
                    decision,

                violations =
                    violations
            )
    }

    // =========================================================================
    // Trust Evaluation
    // =========================================================================

    /**
     * Performs trust evaluation through CertificateTrustManager.
     *
     * The exact trust-manager API may vary as the SentriX trust layer evolves.
     * Reflection is deliberately avoided here; this method should be adapted
     * to the concrete trust API used by the project.
     */
    private fun performTrustCheck(
        certificate: X509Certificate
    ): CertificateTrustAssessment {

        /*
         * CertificateTrustManager is intentionally kept behind an adapter
         * boundary in this class.
         *
         * If CertificateTrustManager exposes a dedicated check method,
         * map its result here.
         *
         * Until that contract is fixed, the checker reports that trust
         * evaluation is delegated but unavailable rather than pretending
         * that the certificate is trusted.
         */
        return CertificateTrustAssessment
            .NotChecked(
                reason =
                    "Trust evaluation must be supplied by " +
                            "CertificateTrustManager."
            )
    }

    // =========================================================================
    // Violation Collection
    // =========================================================================

    /**
     * Collects all security violations from the individual checks.
     */
    private fun collectViolations(
        expiration:
            CertificateExpirationResult,

        revocation:
            CertificateRevocationResult,

        trust:
            CertificateTrustAssessment,

        pin:
            CertificatePinAssessment,

        configuration:
            CertificateSecurityConfiguration
    ): List<CertificateSecurityViolation> {

        val violations =
            mutableListOf<
                    CertificateSecurityViolation
                    >()

        // ---------------------------------------------------------------------
        // Expiration
        // ---------------------------------------------------------------------

        when (
            expiration
        ) {

            is CertificateExpirationResult.Expired -> {

                violations +=
                    CertificateSecurityViolation
                        .CertificateExpired
            }

            is CertificateExpirationResult.NotYetValid -> {

                violations +=
                    CertificateSecurityViolation
                        .CertificateNotYetValid
            }

            is CertificateExpirationResult
                .InvalidValidityPeriod -> {

                violations +=
                    CertificateSecurityViolation
                        .InvalidValidityPeriod
            }

            is CertificateExpirationResult.ExpiringSoon -> {

                when (
                    expiration.warning
                ) {

                    CertificateExpirationWarning.CRITICAL ->
                        violations +=
                            CertificateSecurityViolation
                                .CertificateExpiringCritically

                    CertificateExpirationWarning.WARNING ->
                        violations +=
                            CertificateSecurityViolation
                                .CertificateExpiringSoon

                    CertificateExpirationWarning.INFO ->
                        violations +=
                            CertificateSecurityViolation
                                .CertificateExpirationWarning

                    CertificateExpirationWarning.NONE ->
                        Unit
                }
            }

            is CertificateExpirationResult.Valid,
            is CertificateExpirationResult.ConfigurationError ->
                Unit
        }

        // ---------------------------------------------------------------------
        // Revocation
        // ---------------------------------------------------------------------

        when (
            revocation
        ) {

            is CertificateRevocationResult.Revoked -> {

                violations +=
                    CertificateSecurityViolation
                        .CertificateRevoked
            }

            is CertificateRevocationResult.Unavailable -> {

                if (
                    configuration
                        .revocationPolicy
                        .unavailableAction ==
                    RevocationUnavailableAction
                        .FAIL_CLOSED
                ) {

                    violations +=
                        CertificateSecurityViolation
                            .RevocationStatusUnavailable

                } else {

                    violations +=
                        CertificateSecurityViolation
                            .RevocationCheckWarning
                }
            }

            is CertificateRevocationResult.ConfigurationError -> {

                violations +=
                    CertificateSecurityViolation
                        .RevocationConfigurationError
            }

            is CertificateRevocationResult.NotRevoked ->
                Unit
        }

        // ---------------------------------------------------------------------
        // Trust
        // ---------------------------------------------------------------------

        when (
            trust
        ) {

            is CertificateTrustAssessment
                .Untrusted -> {

                violations +=
                    CertificateSecurityViolation
                        .CertificateUntrusted
            }

            is CertificateTrustAssessment
                .TrustEvaluationFailed -> {

                violations +=
                    CertificateSecurityViolation
                        .TrustEvaluationFailed
            }

            is CertificateTrustAssessment
                .NotChecked -> {

                if (
                    configuration.requireTrustEvaluation
                ) {

                    violations +=
                        CertificateSecurityViolation
                            .TrustEvaluationUnavailable
                }
            }

            is CertificateTrustAssessment
                .Trusted ->
                Unit
        }

        // ---------------------------------------------------------------------
        // Pinning
        // ---------------------------------------------------------------------

        when (
            pin
        ) {

            is CertificatePinAssessment
                .Matched ->
                Unit

            is CertificatePinAssessment
                .Mismatch -> {

                violations +=
                    CertificateSecurityViolation
                        .CertificatePinMismatch
            }

            is CertificatePinAssessment
                .ConfigurationMissing -> {

                if (
                    configuration.requirePinConfiguration
                ) {

                    violations +=
                        CertificateSecurityViolation
                            .PinConfigurationMissing
                }
            }

            is CertificatePinAssessment
                .NotChecked -> {

                if (
                    configuration.requirePinEvaluation
                ) {

                    violations +=
                        CertificateSecurityViolation
                            .PinEvaluationUnavailable
                }
            }
        }

        return violations.distinct()
    }

    // =========================================================================
    // Risk Calculation
    // =========================================================================

    /**
     * Calculates overall certificate security risk.
     */
    private fun calculateRisk(
        expiration:
            CertificateExpirationResult,

        revocation:
            CertificateRevocationResult,

        trust:
            CertificateTrustAssessment,

        pin:
            CertificatePinAssessment,

        violations:
            List<CertificateSecurityViolation>
    ): CertificateSecurityRisk {

        /*
         * Hard security failures.
         */
        if (
            violations.any {
                it.severity ==
                        CertificateViolationSeverity
                            .CRITICAL
            }
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        /*
         * High-severity violations.
         */
        if (
            violations.any {
                it.severity ==
                        CertificateViolationSeverity
                            .HIGH
            }
        ) {

            return CertificateSecurityRisk
                .HIGH
        }

        /*
         * Medium-severity issues.
         */
        if (
            violations.any {
                it.severity ==
                        CertificateViolationSeverity
                            .MEDIUM
            }
        ) {

            return CertificateSecurityRisk
                .MEDIUM
        }

        /*
         * Informational warnings.
         */
        if (
            violations.any {
                it.severity ==
                        CertificateViolationSeverity
                            .LOW
            }
        ) {

            return CertificateSecurityRisk
                .LOW
        }

        /*
         * Explicitly inspect the core results as a final safeguard.
         */
        if (
            revocation is
            CertificateRevocationResult.Revoked
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        if (
            expiration is
            CertificateExpirationResult.Expired
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        if (
            pin is
            CertificatePinAssessment.Mismatch
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        if (
            trust is
            CertificateTrustAssessment.Untrusted
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        return CertificateSecurityRisk
            .SAFE
    }

    /**
     * Calculates overall chain security risk.
     */
    private fun calculateChainRisk(
        individualResults:
            List<CertificateChainCertificateSecurity>,

        expirationResult:
            CertificateChainExpirationResult,

        revocationResult:
            CertificateChainRevocationResult
    ): CertificateSecurityRisk {

        if (
            revocationResult is
            CertificateChainRevocationResult.Revoked
        ) {

            return CertificateSecurityRisk
                .CRITICAL
        }

        if (
            expirationResult is
            CertificateChainExpirationResult.Evaluated
        ) {

            when (
                expirationResult.status
            ) {

                CertificateChainExpirationStatus
                    .EXPIRED,

                CertificateChainExpirationStatus
                    .INVALID,

                CertificateChainExpirationStatus
                    .NOT_YET_VALID ->

                    return CertificateSecurityRisk
                        .CRITICAL

                CertificateChainExpirationStatus
                    .CRITICAL ->

                    return CertificateSecurityRisk
                        .HIGH

                CertificateChainExpirationStatus
                    .EXPIRING_SOON ->

                    return CertificateSecurityRisk
                        .MEDIUM

                CertificateChainExpirationStatus
                    .VALID ->
                    Unit
            }
        }

        val highestIndividualRisk =
            individualResults
                .maxByOrNull {
                    it.result.risk.priority
                }
                ?.result
                ?.risk

        return highestIndividualRisk
            ?: CertificateSecurityRisk
                .SAFE
    }

    // =========================================================================
    // Security Decision
    // =========================================================================

    /**
     * Converts risk and violations into an explicit security decision.
     */
    private fun determineDecision(
        risk:
            CertificateSecurityRisk,

        violations:
            List<CertificateSecurityViolation>,

        configuration:
            CertificateSecurityConfiguration
    ): CertificateSecurityDecision {

        if (
            violations.any {
                it.isBlocking
            }
        ) {

            return CertificateSecurityDecision
                .BLOCK
        }

        return when (
            risk
        ) {

            CertificateSecurityRisk.CRITICAL ->
                CertificateSecurityDecision
                    .BLOCK

            CertificateSecurityRisk.HIGH ->

                if (
                    configuration
                        .blockHighRiskCertificates
                ) {

                    CertificateSecurityDecision
                        .BLOCK

                } else {

                    CertificateSecurityDecision
                        .WARN
                }

            CertificateSecurityRisk.MEDIUM,
            CertificateSecurityRisk.LOW ->

                CertificateSecurityDecision
                    .WARN

            CertificateSecurityRisk.SAFE ->
                CertificateSecurityDecision
                    .ALLOW
        }
    }

    // =========================================================================
    // Recommendations
    // =========================================================================

    /**
     * Generates actionable security recommendations.
     */
    private fun generateRecommendations(
        expiration:
            CertificateExpirationResult,

        revocation:
            CertificateRevocationResult,

        trust:
            CertificateTrustAssessment,

        pin:
            CertificatePinAssessment,

        risk:
            CertificateSecurityRisk
    ): List<CertificateSecurityRecommendation> {

        val recommendations =
            mutableListOf<
                    CertificateSecurityRecommendation
                    >()

        when (
            expiration
        ) {

            is CertificateExpirationResult.Expired ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .RenewExpiredCertificate

            is CertificateExpirationResult.NotYetValid ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .CheckDeviceClockAndCertificate

            is CertificateExpirationResult.ExpiringSoon -> {

                when (
                    expiration.warning
                ) {

                    CertificateExpirationWarning.CRITICAL,
                    CertificateExpirationWarning.WARNING ->

                        recommendations +=
                            CertificateSecurityRecommendation
                                .RenewCertificateSoon

                    CertificateExpirationWarning.INFO ->

                        recommendations +=
                            CertificateSecurityRecommendation
                                .PlanCertificateRenewal

                    CertificateExpirationWarning.NONE ->
                        Unit
                }
            }

            else ->
                Unit
        }

        when (
            revocation
        ) {

            is CertificateRevocationResult.Revoked ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .BlockCertificate

            is CertificateRevocationResult.Unavailable ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .RetryRevocationCheck

            else ->
                Unit
        }

        when (
            trust
        ) {

            is CertificateTrustAssessment.Untrusted ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .RejectUntrustedCertificate

            is CertificateTrustAssessment
                .TrustEvaluationFailed ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .InvestigateTrustFailure

            is CertificateTrustAssessment
                .NotChecked ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .PerformTrustValidation

            is CertificateTrustAssessment.Trusted ->
                Unit
        }

        when (
            pin
        ) {

            is CertificatePinAssessment.Mismatch ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .BlockPinMismatch

            is CertificatePinAssessment
                .ConfigurationMissing ->

                recommendations +=
                    CertificateSecurityRecommendation
                        .ConfigureCertificatePins

            is CertificatePinAssessment
                .NotChecked ->
                Unit

            is CertificatePinAssessment
                .Matched ->
                Unit
        }

        if (
            risk ==
            CertificateSecurityRisk.CRITICAL
        ) {

            recommendations +=
                CertificateSecurityRecommendation
                    .EscalateSecurityIncident
        }

        return recommendations
            .distinct()
    }

    // =========================================================================
    // Configuration Validation
    // =========================================================================

    /**
     * Validates the security-check configuration.
     */
    private fun validateConfiguration(
        configuration:
            CertificateSecurityConfiguration
    ): String? {

        if (
            configuration.hostname != null &&
            configuration.hostname.isBlank()
        ) {

            return "Hostname must not be blank."
        }

        return null
    }

    // =========================================================================
    // Convenience APIs
    // =========================================================================

    /**
     * Returns true when the certificate passes the configured
     * security policy.
     */
    fun isSecure(
        certificate: X509Certificate
    ): Boolean {

        val result =
            check(
                certificate
            )

        return result is
                CertificateSecurityResult.Evaluated &&
                result.decision ==
                CertificateSecurityDecision.ALLOW
    }

    /**
     * Returns true when the certificate must be blocked.
     */
    fun shouldBlock(
        certificate: X509Certificate
    ): Boolean {

        val result =
            check(
                certificate
            )

        return result is
                CertificateSecurityResult.Evaluated &&
                result.decision ==
                CertificateSecurityDecision.BLOCK
    }

    /**
     * Returns true when the certificate requires a warning.
     */
    fun requiresWarning(
        certificate: X509Certificate
    ): Boolean {

        val result =
            check(
                certificate
            )

        return result is
                CertificateSecurityResult.Evaluated &&
                result.decision ==
                CertificateSecurityDecision.WARN
    }

    /**
     * Returns the security risk for a certificate.
     */
    fun getRisk(
        certificate: X509Certificate
    ): CertificateSecurityRisk {

        val result =
            check(
                certificate
            )

        return when (
            result
        ) {

            is CertificateSecurityResult.Evaluated ->
                result.risk

            else ->
                CertificateSecurityRisk
                    .CRITICAL
        }
    }

    /**
     * Returns all security violations.
     */
    fun getViolations(
        certificate: X509Certificate
    ): List<CertificateSecurityViolation> {

        val result =
            check(
                certificate
            )

        return when (
            result
        ) {

            is CertificateSecurityResult.Evaluated ->
                result.violations

            else ->
                listOf(
                    CertificateSecurityViolation
                        .SecurityCheckFailure
                )
        }
    }
}

/**
 * Configuration for the complete certificate security assessment.
 */
data class CertificateSecurityConfiguration(

    /**
     * Hostname used for certificate pinning.
     */
    val hostname: String? = null,

    /**
     * Whether expiration checking is performed.
     *
     * Expiration checking is normally always enabled.
     */
    val checkExpiration: Boolean = true,

    /**
     * Whether revocation checking is performed.
     */
    val checkRevocation: Boolean = true,

    /**
     * Whether certificate trust checking is performed.
     */
    val checkTrust: Boolean = true,

    /**
     * Whether certificate pinning is performed.
     */
    val checkPinning: Boolean = false,

    /**
     * Whether the hostname must have pin configuration when pinning
     * is enabled.
     */
    val requirePinConfiguration: Boolean = true,

    /**
     * Whether pin evaluation itself is mandatory.
     */
    val requirePinEvaluation: Boolean = false,

    /**
     * Whether trust evaluation is mandatory.
     */
    val requireTrustEvaluation: Boolean = true,

    /**
     * Whether high-risk certificates should be blocked.
     */
    val blockHighRiskCertificates: Boolean = true,

    /**
     * Expiration configuration.
     */
    val expirationConfiguration:
        CertificateExpirationConfiguration =
        CertificateExpirationConfiguration.default(),

    /**
     * Revocation configuration.
     */
    val revocationPolicy:
        CertificateRevocationPolicy =
        CertificateRevocationPolicy.default()
) {

    companion object {

        /**
         * Default SentriX security configuration.
         */
        fun default():
                CertificateSecurityConfiguration {

            return CertificateSecurityConfiguration()
        }

        /**
         * Strict configuration suitable for highly sensitive
         * security operations.
         */
        fun strict(
            hostname: String? = null
        ): CertificateSecurityConfiguration {

            return CertificateSecurityConfiguration(

                hostname =
                    hostname,

                checkExpiration =
                    true,

                checkRevocation =
                    true,

                checkTrust =
                    true,

                checkPinning =
                    true,

                requirePinConfiguration =
                    true,

                requirePinEvaluation =
                    true,

                requireTrustEvaluation =
                    true,

                blockHighRiskCertificates =
                    true,

                expirationConfiguration =
                    CertificateExpirationConfiguration
                        .strict(),

                revocationPolicy =
                    CertificateRevocationPolicy
                        .strict()
            )
        }

        /**
         * Network-protection configuration.
         *
         * Designed for use before establishing a sensitive
         * network connection.
         */
        fun networkProtection(
            hostname: String
        ): CertificateSecurityConfiguration {

            return CertificateSecurityConfiguration(

                hostname =
                    hostname,

                checkExpiration =
                    true,

                checkRevocation =
                    true,

                checkTrust =
                    true,

                checkPinning =
                    true,

                requirePinConfiguration =
                    true,

                requirePinEvaluation =
                    true,

                requireTrustEvaluation =
                    true,

                blockHighRiskCertificates =
                    true,

                expirationConfiguration =
                    CertificateExpirationConfiguration
                        .strict(),

                revocationPolicy =
                    CertificateRevocationPolicy
                        .strict()
            )
        }

        /**
         * Monitoring-oriented configuration.
         *
         * Useful when collecting telemetry without immediately
         * blocking the connection.
         */
        fun monitoring():
                CertificateSecurityConfiguration {

            return CertificateSecurityConfiguration(

                checkExpiration =
                    true,

                checkRevocation =
                    true,

                checkTrust =
                    true,

                checkPinning =
                    false,

                requireTrustEvaluation =
                    false,

                blockHighRiskCertificates =
                    false,

                revocationPolicy =
                    CertificateRevocationPolicy
                        .compatibility()
            )
        }
    }
}

/**
 * Complete certificate security result.
 */
sealed class CertificateSecurityResult {

    /**
     * Certificate has been comprehensively evaluated.
     */
    data class Evaluated(

        val certificateFingerprint:
            CertificateFingerprint,

        val expiration:
            CertificateExpirationResult,

        val revocation:
            CertificateRevocationResult,

        val trust:
            CertificateTrustAssessment,

        val pinning:
            CertificatePinAssessment,

        val risk:
            CertificateSecurityRisk,

        val decision:
            CertificateSecurityDecision,

        val violations:
            List<CertificateSecurityViolation>,

        val recommendations:
            List<CertificateSecurityRecommendation>

    ) : CertificateSecurityResult()

    /**
     * Fingerprint generation failed.
     */
    data class FingerprintFailure(
        val cause: Throwable
    ) : CertificateSecurityResult()

    /**
     * Security-check configuration is invalid.
     */
    data class ConfigurationError(
        val reason: String
    ) : CertificateSecurityResult()
}

/**
 * Trust assessment abstraction used by CertificateSecurityChecker.
 */
sealed class CertificateTrustAssessment {

    /**
     * Certificate has been trusted by the trust subsystem.
     */
    data object Trusted :
        CertificateTrustAssessment()

    /**
     * Certificate was explicitly determined to be untrusted.
     */
    data class Untrusted(
        val reason: String
    ) : CertificateTrustAssessment()

    /**
     * Trust evaluation failed.
     */
    data class TrustEvaluationFailed(
        val reason: String
    ) : CertificateTrustAssessment()

    /**
     * Trust evaluation was not performed.
     */
    data class NotChecked(
        val reason: String
    ) : CertificateTrustAssessment()
}

/**
 * Pin assessment abstraction.
 */
sealed class CertificatePinAssessment {

    /**
     * Certificate matched a configured pin.
     */
    data class Matched(
        val pinType:
            CertificatePinType,
        val isBackup: Boolean
    ) : CertificatePinAssessment()

    /**
     * Certificate failed pin validation.
     */
    data class Mismatch(
        val reason: String
    ) : CertificatePinAssessment()

    /**
     * No pin configuration exists.
     */
    data class ConfigurationMissing(
        val host: String
    ) : CertificatePinAssessment()

    /**
     * Pin evaluation was not performed.
     */
    data class NotChecked(
        val reason: String
    ) : CertificatePinAssessment()
}

/**
 * Overall certificate security risk.
 */
enum class CertificateSecurityRisk(

    /**
     * Higher value means higher security risk.
     */
    val priority: Int
) {

    SAFE(
        priority = 0
    ),

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

/**
 * Final certificate security decision.
 */
enum class CertificateSecurityDecision {

    /**
     * Certificate can proceed under the evaluated policy.
     */
    ALLOW,

    /**
     * Certificate may proceed but requires warning/telemetry.
     */
    WARN,

    /**
     * Certificate should be rejected.
     */
    BLOCK
}

/**
 * Severity of a certificate security violation.
 */
enum class CertificateViolationSeverity(
    val priority: Int
) {

    LOW(
        priority = 1
    ),

    MEDIUM(
        priority = 2
    ),

    HIGH(
        priority = 3
    ),

    CRITICAL(
        priority = 4
    )
}

/**
 * Individual security violations detected during assessment.
 */
enum class CertificateSecurityViolation(

    /**
     * Security severity.
     */
    val severity:
        CertificateViolationSeverity,

    /**
     * Whether the violation should block the certificate.
     */
    val isBlocking: Boolean
) {

    CertificateExpired(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    CertificateNotYetValid(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    InvalidValidityPeriod(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    CertificateRevoked(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    CertificateUntrusted(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    CertificatePinMismatch(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    ),

    RevocationStatusUnavailable(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    TrustEvaluationUnavailable(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    TrustEvaluationFailed(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    PinConfigurationMissing(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    PinEvaluationUnavailable(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    CertificateExpiringCritically(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            false
    ),

    CertificateExpiringSoon(
        severity =
            CertificateViolationSeverity.MEDIUM,
        isBlocking =
            false
    ),

    RevocationConfigurationError(
        severity =
            CertificateViolationSeverity.HIGH,
        isBlocking =
            true
    ),

    CertificateExpirationWarning(
        severity =
            CertificateViolationSeverity.LOW,
        isBlocking =
            false
    ),

    RevocationCheckWarning(
        severity =
            CertificateViolationSeverity.LOW,
        isBlocking =
            false
    ),

    SecurityCheckFailure(
        severity =
            CertificateViolationSeverity.CRITICAL,
        isBlocking =
            true
    )
}

/**
 * Recommended action for a certificate security issue.
 */
enum class CertificateSecurityRecommendation {

    RenewExpiredCertificate,

    RenewCertificateSoon,

    PlanCertificateRenewal,

    CheckDeviceClockAndCertificate,

    BlockCertificate,

    RetryRevocationCheck,

    RejectUntrustedCertificate,

    InvestigateTrustFailure,

    PerformTrustValidation,

    BlockPinMismatch,

    ConfigureCertificatePins,

    EscalateSecurityIncident
}

/**
 * Result of checking an entire certificate chain.
 */
sealed class CertificateChainSecurityResult {

    /**
     * No certificates were supplied.
     */
    data object EmptyChain :
        CertificateChainSecurityResult()

    /**
     * Chain has been fully evaluated.
     */
    data class Evaluated(

        val certificates:
            List<CertificateChainCertificateSecurity>,

        val expiration:
            CertificateChainExpirationResult,

        val revocation:
            CertificateChainRevocationResult,

        val risk:
            CertificateSecurityRisk,

        val decision:
            CertificateSecurityDecision,

        val violations:
            List<CertificateSecurityViolation>

    ) : CertificateChainSecurityResult()
}

/**
 * Security assessment for one certificate inside a chain.
 */
data class CertificateChainCertificateSecurity(

    /**
     * Certificate position:
     *
     * 0 = leaf
     * 1 = intermediate
     * last = root
     */
    val index: Int,

    val certificate:
        X509Certificate,

    val result:
        CertificateSecurityResult.Evaluated
)
