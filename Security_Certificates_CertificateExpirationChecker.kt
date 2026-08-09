package com.sentrix.security.certificates

import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.TimeUnit

/**
 * SentriX Certificate Expiration Checker
 *
 * Enterprise-grade certificate lifetime monitoring component.
 *
 * Responsibilities:
 *
 * - Detect expired certificates.
 * - Detect certificates that are not yet valid.
 * - Calculate remaining certificate lifetime.
 * - Detect certificates approaching expiration.
 * - Validate certificate validity at a specific point in time.
 * - Check complete certificate chains.
 * - Identify the certificate with the shortest remaining lifetime.
 * - Provide expiration-risk assessments.
 * - Support configurable warning thresholds.
 *
 * This class DOES NOT:
 *
 * - Decide whether a certificate is trusted.
 * - Perform PKIX validation.
 * - Perform SSL pinning.
 * - Modify certificates.
 * - Renew certificates.
 * - Contact certificate authorities.
 * - Ignore certificate expiration.
 *
 * Certificate trust belongs to:
 *
 *      CertificateTrustManager
 *
 * Certificate-chain validation belongs to:
 *
 *      CertificateChainValidator
 *
 * Pinning belongs to:
 *
 *      CertificatePinManager
 *
 * Architecture:
 *
 *      X509Certificate
 *             │
 *             ▼
 *      CertificateExpirationChecker
 *             │
 *       ┌─────┼───────────────┐
 *       ▼     ▼               ▼
 *    Expired  Valid       Expiring Soon
 *       │     │               │
 *       └─────┼───────────────┘
 *             ▼
 *      ExpirationAssessment
 */
class CertificateExpirationChecker {

    // =========================================================================
    // Main Certificate Check
    // =========================================================================

    /**
     * Performs an expiration check using the default configuration.
     */
    fun check(
        certificate: X509Certificate
    ): CertificateExpirationResult {

        return check(
            certificate = certificate,
            configuration =
                CertificateExpirationConfiguration.default()
        )
    }

    /**
     * Performs a certificate expiration check using a custom configuration.
     */
    fun check(
        certificate: X509Certificate,
        configuration: CertificateExpirationConfiguration
    ): CertificateExpirationResult {

        val validation =
            validateConfiguration(
                configuration
            )

        if (
            validation != null
        ) {

            return CertificateExpirationResult
                .ConfigurationError(
                    validation
                )
        }

        val now =
            configuration.currentTimeMillis

        val notBefore =
            certificate.notBefore.time

        val notAfter =
            certificate.notAfter.time

        // ---------------------------------------------------------------------
        // Invalid certificate date range
        // ---------------------------------------------------------------------

        if (
            notAfter < notBefore
        ) {

            return CertificateExpirationResult
                .InvalidValidityPeriod(
                    notBefore = notBefore,
                    notAfter = notAfter
                )
        }

        // ---------------------------------------------------------------------
        // Not yet valid
        // ---------------------------------------------------------------------

        if (
            now < notBefore
        ) {

            return CertificateExpirationResult
                .NotYetValid(
                    validFromMillis =
                        notBefore,
                    validUntilMillis =
                        notAfter,
                    millisecondsUntilValid =
                        notBefore - now
                )
        }

        // ---------------------------------------------------------------------
        // Expired
        // ---------------------------------------------------------------------

        if (
            now > notAfter
        ) {

            return CertificateExpirationResult
                .Expired(
                    expiredAtMillis =
                        notAfter,
                    millisecondsSinceExpiration =
                        now - notAfter
                )
        }

        // ---------------------------------------------------------------------
        // Valid certificate
        // ---------------------------------------------------------------------

        val remainingMillis =
            notAfter - now

        val remainingDays =
            millisToDays(
                remainingMillis
            )

        val warning =
            determineWarningLevel(
                remainingMillis =
                    remainingMillis,
                configuration =
                    configuration
            )

        return when (
            warning
        ) {

            CertificateExpirationWarning.NONE ->
                CertificateExpirationResult.Valid(
                    validFromMillis =
                        notBefore,
                    validUntilMillis =
                        notAfter,
                    remainingMillis =
                        remainingMillis,
                    remainingDays =
                        remainingDays
                )

            CertificateExpirationWarning.INFO ->
                CertificateExpirationResult.ExpiringSoon(
                    validFromMillis =
                        notBefore,
                    validUntilMillis =
                        notAfter,
                    remainingMillis =
                        remainingMillis,
                    remainingDays =
                        remainingDays,
                    warning =
                        warning
                )

            CertificateExpirationWarning.WARNING ->
                CertificateExpirationResult.ExpiringSoon(
                    validFromMillis =
                        notBefore,
                    validUntilMillis =
                        notAfter,
                    remainingMillis =
                        remainingMillis,
                    remainingDays =
                        remainingDays,
                    warning =
                        warning
                )

            CertificateExpirationWarning.CRITICAL ->
                CertificateExpirationResult.ExpiringSoon(
                    validFromMillis =
                        notBefore,
                    validUntilMillis =
                        notAfter,
                    remainingMillis =
                        remainingMillis,
                    remainingDays =
                        remainingDays,
                    warning =
                        warning
                )
        }
    }

    // =========================================================================
    // Date Validation
    // =========================================================================

    /**
     * Validates the certificate at the current system time.
     */
    fun isCurrentlyValid(
        certificate: X509Certificate
    ): Boolean {

        return isValidAt(
            certificate =
                certificate,
            timeMillis =
                System.currentTimeMillis()
        )
    }

    /**
     * Determines whether the certificate is valid at a specific time.
     */
    fun isValidAt(
        certificate: X509Certificate,
        timeMillis: Long
    ): Boolean {

        val notBefore =
            certificate.notBefore.time

        val notAfter =
            certificate.notAfter.time

        return timeMillis >= notBefore &&
                timeMillis <= notAfter
    }

    /**
     * Determines whether the certificate has expired.
     */
    fun isExpired(
        certificate: X509Certificate
    ): Boolean {

        return System.currentTimeMillis() >
                certificate.notAfter.time
    }

    /**
     * Determines whether the certificate is not yet valid.
     */
    fun isNotYetValid(
        certificate: X509Certificate
    ): Boolean {

        return System.currentTimeMillis() <
                certificate.notBefore.time
    }

    /**
     * Determines whether the certificate is currently valid.
     */
    fun isValid(
        certificate: X509Certificate
    ): Boolean {

        return !isExpired(
            certificate
        ) &&
                !isNotYetValid(
                    certificate
                )
    }

    // =========================================================================
    // Remaining Lifetime
    // =========================================================================

    /**
     * Returns the remaining lifetime in milliseconds.
     *
     * Returns:
     *
     * - Positive value when still valid.
     * - Zero when expiration has just been reached.
     * - Negative value when expired.
     */
    fun getRemainingMillis(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Long {

        return certificate.notAfter.time -
                currentTimeMillis
    }

    /**
     * Returns remaining lifetime in seconds.
     */
    fun getRemainingSeconds(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Long {

        return TimeUnit.MILLISECONDS.toSeconds(
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )
        )
    }

    /**
     * Returns remaining lifetime in minutes.
     */
    fun getRemainingMinutes(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Long {

        return TimeUnit.MILLISECONDS.toMinutes(
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )
        )
    }

    /**
     * Returns remaining lifetime in hours.
     */
    fun getRemainingHours(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Long {

        return TimeUnit.MILLISECONDS.toHours(
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )
        )
    }

    /**
     * Returns remaining lifetime in days.
     */
    fun getRemainingDays(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Long {

        return TimeUnit.MILLISECONDS.toDays(
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )
        )
    }

    // =========================================================================
    // Validity Duration
    // =========================================================================

    /**
     * Returns the total certificate validity period in milliseconds.
     */
    fun getValidityDurationMillis(
        certificate: X509Certificate
    ): Long {

        return certificate.notAfter.time -
                certificate.notBefore.time
    }

    /**
     * Returns total certificate validity period in days.
     */
    fun getValidityDurationDays(
        certificate: X509Certificate
    ): Long {

        return millisToDays(
            getValidityDurationMillis(
                certificate
            )
        )
    }

    /**
     * Returns the percentage of certificate lifetime remaining.
     */
    fun getRemainingLifetimePercentage(
        certificate: X509Certificate,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Double {

        val totalLifetime =
            getValidityDurationMillis(
                certificate
            )

        if (
            totalLifetime <= 0L
        ) {

            return 0.0
        }

        val remaining =
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )

        if (
            remaining <= 0L
        ) {

            return 0.0
        }

        if (
            remaining >= totalLifetime
        ) {

            return 100.0
        }

        return (
            remaining.toDouble() /
                    totalLifetime.toDouble()
            ) * 100.0
    }

    // =========================================================================
    // Expiration Thresholds
    // =========================================================================

    /**
     * Determines whether a certificate expires within the specified
     * number of days.
     */
    fun expiresWithinDays(
        certificate: X509Certificate,
        days: Long,
        currentTimeMillis: Long =
            System.currentTimeMillis()
    ): Boolean {

        require(
            days >= 0
        ) {
            "Days must not be negative."
        }

        val remaining =
            getRemainingMillis(
                certificate,
                currentTimeMillis
            )

        val threshold =
            TimeUnit.DAYS.toMillis(
                days
            )

        return remaining in 0..threshold
    }

    /**
     * Determines whether a certificate expires within the configured
     * warning window.
     */
    fun isExpiringSoon(
        certificate: X509Certificate,
        configuration:
            CertificateExpirationConfiguration =
            CertificateExpirationConfiguration.default()
    ): Boolean {

        val remaining =
            getRemainingMillis(
                certificate,
                configuration.currentTimeMillis
            )

        return remaining > 0L &&
                remaining <=
                configuration.warningThresholdMillis
    }

    /**
     * Determines whether a certificate is in the critical expiration
     * window.
     */
    fun isCriticallyExpiring(
        certificate: X509Certificate,
        configuration:
            CertificateExpirationConfiguration =
            CertificateExpirationConfiguration.default()
    ): Boolean {

        val remaining =
            getRemainingMillis(
                certificate,
                configuration.currentTimeMillis
            )

        return remaining > 0L &&
                remaining <=
                configuration.criticalThresholdMillis
    }

    /**
     * Determines whether a certificate expires within 24 hours.
     */
    fun expiresWithin24Hours(
        certificate: X509Certificate
    ): Boolean {

        return expiresWithinDays(
            certificate = certificate,
            days = 1
        )
    }

    /**
     * Determines whether a certificate expires within seven days.
     */
    fun expiresWithin7Days(
        certificate: X509Certificate
    ): Boolean {

        return expiresWithinDays(
            certificate = certificate,
            days = 7
        )
    }

    /**
     * Determines whether a certificate expires within thirty days.
     */
    fun expiresWithin30Days(
        certificate: X509Certificate
    ): Boolean {

        return expiresWithinDays(
            certificate = certificate,
            days = 30
        )
    }

    // =========================================================================
    // Certificate Chain Checks
    // =========================================================================

    /**
     * Checks the expiration status of every certificate in a chain.
     *
     * Expected order:
     *
     *      Leaf -> Intermediate -> Root
     */
    fun checkChain(
        certificateChain: List<X509Certificate>
    ): CertificateChainExpirationResult {

        return checkChain(
            certificateChain =
                certificateChain,
            configuration =
                CertificateExpirationConfiguration
                    .default()
        )
    }

    /**
     * Performs a complete expiration assessment for a certificate chain.
     */
    fun checkChain(
        certificateChain: List<X509Certificate>,
        configuration:
            CertificateExpirationConfiguration
    ): CertificateChainExpirationResult {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainExpirationResult
                .EmptyChain
        }

        val results =
            certificateChain.mapIndexed {
                index,
                certificate ->

                CertificateChainCertificateExpiration(
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

        val expired =
            results.filter {
                it.result is
                        CertificateExpirationResult.Expired
            }

        val notYetValid =
            results.filter {
                it.result is
                        CertificateExpirationResult.NotYetValid
            }

        val expiringSoon =
            results.filter {
                it.result is
                        CertificateExpirationResult.ExpiringSoon
            }

        val invalid =
            results.filter {
                it.result is
                        CertificateExpirationResult.InvalidValidityPeriod
            }

        val valid =
            results.filter {
                it.result is
                        CertificateExpirationResult.Valid
            }

        val status =
            when {

                invalid.isNotEmpty() ->
                    CertificateChainExpirationStatus
                        .INVALID

                expired.isNotEmpty() ->
                    CertificateChainExpirationStatus
                        .EXPIRED

                notYetValid.isNotEmpty() ->
                    CertificateChainExpirationStatus
                        .NOT_YET_VALID

                expiringSoon.any {
                    val result =
                        it.result

                    result is
                            CertificateExpirationResult.ExpiringSoon &&
                            result.warning ==
                            CertificateExpirationWarning.CRITICAL
                } ->
                    CertificateChainExpirationStatus
                        .CRITICAL

                expiringSoon.isNotEmpty() ->
                    CertificateChainExpirationStatus
                        .EXPIRING_SOON

                else ->
                    CertificateChainExpirationStatus
                        .VALID
            }

        return CertificateChainExpirationResult
            .Evaluated(
                status =
                    status,
                certificates =
                    results,
                expiredCount =
                    expired.size,
                notYetValidCount =
                    notYetValid.size,
                expiringSoonCount =
                    expiringSoon.size,
                validCount =
                    valid.size
            )
    }

    /**
     * Returns the certificate with the shortest remaining lifetime.
     */
    fun findEarliestExpiration(
        certificateChain:
            List<X509Certificate>
    ): CertificateChainCertificateExpiration? {

        if (
            certificateChain.isEmpty()
        ) {

            return null
        }

        val now =
            System.currentTimeMillis()

        return certificateChain
            .mapIndexed { index, certificate ->

                CertificateChainCertificateExpiration(
                    index =
                        index,
                    certificate =
                        certificate,
                    result =
                        check(
                            certificate
                        )
                )
            }
            .minByOrNull {
                it.certificate
                    .notAfter
                    .time
            }
    }

    /**
     * Returns all currently expired certificates in the chain.
     */
    fun getExpiredCertificates(
        certificateChain:
            List<X509Certificate>
    ): List<X509Certificate> {

        return certificateChain.filter {
            isExpired(
                it
            )
        }
    }

    /**
     * Returns all certificates that are not yet valid.
     */
    fun getNotYetValidCertificates(
        certificateChain:
            List<X509Certificate>
    ): List<X509Certificate> {

        return certificateChain.filter {
            isNotYetValid(
                it
            )
        }
    }

    /**
     * Returns certificates approaching expiration.
     */
    fun getExpiringCertificates(
        certificateChain:
            List<X509Certificate>,
        thresholdDays: Long
    ): List<X509Certificate> {

        return certificateChain.filter {
            expiresWithinDays(
                certificate = it,
                days =
                    thresholdDays
            )
        }
    }

    // =========================================================================
    // Expiration Risk
    // =========================================================================

    /**
     * Produces a security-oriented expiration risk assessment.
     */
    fun assessRisk(
        certificate: X509Certificate,
        configuration:
            CertificateExpirationConfiguration =
            CertificateExpirationConfiguration.default()
    ): CertificateExpirationRiskAssessment {

        val result =
            check(
                certificate,
                configuration
            )

        val risk =
            when (
                result
            ) {

                is CertificateExpirationResult.Expired ->
                    CertificateExpirationRisk
                        .CRITICAL

                is CertificateExpirationResult.NotYetValid ->
                    CertificateExpirationRisk
                        .CRITICAL

                is CertificateExpirationResult.InvalidValidityPeriod ->
                    CertificateExpirationRisk
                        .CRITICAL

                is CertificateExpirationResult.ExpiringSoon ->

                    when (
                        result.warning
                    ) {

                        CertificateExpirationWarning.CRITICAL ->
                            CertificateExpirationRisk
                                .HIGH

                        CertificateExpirationWarning.WARNING ->
                            CertificateExpirationRisk
                                .MEDIUM

                        CertificateExpirationWarning.INFO ->
                            CertificateExpirationRisk
                                .LOW

                        CertificateExpirationWarning.NONE ->
                            CertificateExpirationRisk
                                .LOW
                    }

                is CertificateExpirationResult.Valid -> {

                    if (
                        result.remainingDays >
                        configuration.safeLifetimeDays
                    ) {

                        CertificateExpirationRisk
                            .LOW

                    } else {

                        CertificateExpirationRisk
                            .MEDIUM
                    }
                }

                is CertificateExpirationResult.ConfigurationError ->
                    CertificateExpirationRisk
                        .UNKNOWN
            }

        return CertificateExpirationRiskAssessment(
            risk =
                risk,
            result =
                result,
            remainingDays =
                getRemainingDays(
                    certificate,
                    configuration.currentTimeMillis
                ),
            remainingPercentage =
                getRemainingLifetimePercentage(
                    certificate,
                    configuration.currentTimeMillis
                )
        )
    }

    /**
     * Produces a chain-wide expiration risk assessment.
     */
    fun assessChainRisk(
        certificateChain:
            List<X509Certificate>,
        configuration:
            CertificateExpirationConfiguration =
            CertificateExpirationConfiguration.default()
    ): CertificateChainExpirationRiskAssessment {

        if (
            certificateChain.isEmpty()
        ) {

            return CertificateChainExpirationRiskAssessment(
                risk =
                    CertificateExpirationRisk
                        .CRITICAL,
                chainResult =
                    CertificateChainExpirationResult
                        .EmptyChain,
                highestRiskIndex =
                    null
            )
        }

        val assessments =
            certificateChain.mapIndexed {
                index,
                certificate ->

                index to
                        assessRisk(
                            certificate,
                            configuration
                        )
            }

        val highestRisk =
            assessments.maxByOrNull {
                it.second.risk.priority
            }

        val chainResult =
            checkChain(
                certificateChain,
                configuration
            )

        return CertificateChainExpirationRiskAssessment(
            risk =
                highestRisk
                    ?.second
                    ?.risk
                    ?: CertificateExpirationRisk
                        .UNKNOWN,
            chainResult =
                chainResult,
            highestRiskIndex =
                highestRisk?.first
        )
    }

    // =========================================================================
    // Expiration Dates
    // =========================================================================

    /**
     * Returns the certificate's expiration date.
     */
    fun getExpirationDate(
        certificate: X509Certificate
    ): Date {

        return certificate.notAfter
    }

    /**
     * Returns the certificate's start-of-validity date.
     */
    fun getValidFromDate(
        certificate: X509Certificate
    ): Date {

        return certificate.notBefore
    }

    /**
     * Returns the expiration timestamp.
     */
    fun getExpirationTimestamp(
        certificate: X509Certificate
    ): Long {

        return certificate.notAfter.time
    }

    /**
     * Returns the validity-start timestamp.
     */
    fun getValidFromTimestamp(
        certificate: X509Certificate
    ): Long {

        return certificate.notBefore.time
    }

    /**
     * Calculates the number of days between now and expiration.
     */
    fun getDaysUntilExpiration(
        certificate: X509Certificate
    ): Long {

        return getRemainingDays(
            certificate
        )
    }

    // =========================================================================
    // Expiration Window
    // =========================================================================

    /**
     * Determines the warning level for remaining certificate lifetime.
     */
    fun determineWarningLevel(
        remainingMillis: Long,
        configuration:
            CertificateExpirationConfiguration
    ): CertificateExpirationWarning {

        if (
            remainingMillis <= 0L
        ) {

            return CertificateExpirationWarning
                .CRITICAL
        }

        return when {

            remainingMillis <=
                    configuration.criticalThresholdMillis ->

                CertificateExpirationWarning
                    .CRITICAL

            remainingMillis <=
                    configuration.warningThresholdMillis ->

                CertificateExpirationWarning
                    .WARNING

            remainingMillis <=
                    configuration.infoThresholdMillis ->

                CertificateExpirationWarning
                    .INFO

            else ->
                CertificateExpirationWarning
                    .NONE
        }
    }

    // =========================================================================
    // Configuration
    // =========================================================================

    /**
     * Validates expiration-check configuration.
     */
    private fun validateConfiguration(
        configuration:
            CertificateExpirationConfiguration
    ): String? {

        if (
            configuration.infoThresholdMillis < 0L
        ) {

            return "Information threshold cannot be negative."
        }

        if (
            configuration.warningThresholdMillis <
            configuration.infoThresholdMillis
        ) {

            return "Warning threshold must be greater than or equal " +
                    "to the information threshold."
        }

        if (
            configuration.criticalThresholdMillis >
            configuration.warningThresholdMillis
        ) {

            return "Critical threshold must not exceed warning threshold."
        }

        if (
            configuration.safeLifetimeDays < 0L
        ) {

            return "Safe lifetime cannot be negative."
        }

        return null
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /**
     * Converts milliseconds to complete days.
     */
    private fun millisToDays(
        millis: Long
    ): Long {

        return TimeUnit.MILLISECONDS.toDays(
            millis
        )
    }
}

/**
 * Configuration controlling certificate expiration monitoring.
 */
data class CertificateExpirationConfiguration(

    /**
     * Time at which validation is performed.
     *
     * Defaults to current system time.
     */
    val currentTimeMillis: Long =
        System.currentTimeMillis(),

    /**
     * Begin informational warning when this much time remains.
     *
     * Default: 90 days.
     */
    val infoThresholdMillis: Long =
        TimeUnit.DAYS.toMillis(
            90
        ),

    /**
     * Begin warning state when this much time remains.
     *
     * Default: 30 days.
     */
    val warningThresholdMillis: Long =
        TimeUnit.DAYS.toMillis(
            30
        ),

    /**
     * Begin critical warning when this much time remains.
     *
     * Default: 7 days.
     */
    val criticalThresholdMillis: Long =
        TimeUnit.DAYS.toMillis(
            7
        ),

    /**
     * Certificates with more than this many days remaining
     * are considered comfortably valid.
     */
    val safeLifetimeDays: Long =
        90
) {

    companion object {

        /**
         * Default SentriX expiration-monitoring configuration.
         */
        fun default():
                CertificateExpirationConfiguration {

            return CertificateExpirationConfiguration()
        }

        /**
         * Strict configuration for high-security environments.
         */
        fun strict():
                CertificateExpirationConfiguration {

            return CertificateExpirationConfiguration(

                infoThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        60
                    ),

                warningThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        21
                    ),

                criticalThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        3
                    ),

                safeLifetimeDays =
                    60
            )
        }

        /**
         * Relaxed configuration for lower-risk environments.
         */
        fun relaxed():
                CertificateExpirationConfiguration {

            return CertificateExpirationConfiguration(

                infoThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        120
                    ),

                warningThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        45
                    ),

                criticalThresholdMillis =
                    TimeUnit.DAYS.toMillis(
                        14
                    ),

                safeLifetimeDays =
                    120
            )
        }
    }
}

/**
 * Result of checking an individual certificate.
 */
sealed class CertificateExpirationResult {

    /**
     * Certificate is currently valid and outside warning windows.
     */
    data class Valid(

        val validFromMillis: Long,

        val validUntilMillis: Long,

        val remainingMillis: Long,

        val remainingDays: Long

    ) : CertificateExpirationResult()

    /**
     * Certificate is valid but approaching expiration.
     */
    data class ExpiringSoon(

        val validFromMillis: Long,

        val validUntilMillis: Long,

        val remainingMillis: Long,

        val remainingDays: Long,

        val warning: CertificateExpirationWarning

    ) : CertificateExpirationResult()

    /**
     * Certificate has expired.
     */
    data class Expired(

        val expiredAtMillis: Long,

        val millisecondsSinceExpiration: Long

    ) : CertificateExpirationResult()

    /**
     * Certificate validity period has not started yet.
     */
    data class NotYetValid(

        val validFromMillis: Long,

        val validUntilMillis: Long,

        val millisecondsUntilValid: Long

    ) : CertificateExpirationResult()

    /**
     * Certificate contains an impossible validity period.
     */
    data class InvalidValidityPeriod(

        val notBefore: Long,

        val notAfter: Long

    ) : CertificateExpirationResult()

    /**
     * Expiration configuration is invalid.
     */
    data class ConfigurationError(
        val reason: String
    ) : CertificateExpirationResult()
}

/**
 * Expiration warning severity.
 */
enum class CertificateExpirationWarning(

    /**
     * Numeric priority for comparison.
     */
    val priority: Int
) {

    /**
     * No expiration warning.
     */
    NONE(
        priority = 0
    ),

    /**
     * Informational warning.
     */
    INFO(
        priority = 1
    ),

    /**
     * Certificate requires attention.
     */
    WARNING(
        priority = 2
    ),

    /**
     * Certificate is close to expiration.
     */
    CRITICAL(
        priority = 3
    )
}

/**
 * Certificate expiration risk.
 */
enum class CertificateExpirationRisk(

    /**
     * Numeric priority.
     */
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
    ),

    UNKNOWN(
        priority = 0
    )
}

/**
 * Expiration risk assessment for one certificate.
 */
data class CertificateExpirationRiskAssessment(

    val risk:
        CertificateExpirationRisk,

    val result:
        CertificateExpirationResult,

    val remainingDays: Long,

    val remainingPercentage: Double
)

/**
 * Expiration status of an entire certificate chain.
 */
enum class CertificateChainExpirationStatus {

    VALID,

    EXPIRING_SOON,

    CRITICAL,

    EXPIRED,

    NOT_YET_VALID,

    INVALID
}

/**
 * Expiration result for a complete certificate chain.
 */
sealed class CertificateChainExpirationResult {

    /**
     * No certificates were supplied.
     */
    data object EmptyChain :
        CertificateChainExpirationResult()

    /**
     * Chain has been evaluated.
     */
    data class Evaluated(

        val status:
            CertificateChainExpirationStatus,

        val certificates:
            List<CertificateChainCertificateExpiration>,

        val expiredCount: Int,

        val notYetValidCount: Int,

        val expiringSoonCount: Int,

        val validCount: Int

    ) : CertificateChainExpirationResult()
}

/**
 * Expiration result associated with a certificate's position
 * within a chain.
 */
data class CertificateChainCertificateExpiration(

    /**
     * Position within the certificate chain.
     *
     * 0 = leaf
     * 1 = intermediate
     * last = root
     */
    val index: Int,

    val certificate:
        X509Certificate,

    val result:
        CertificateExpirationResult
)

/**
 * Chain-wide expiration risk assessment.
 */
data class CertificateChainExpirationRiskAssessment(

    val risk:
        CertificateExpirationRisk,

    val chainResult:
        CertificateChainExpirationResult,

    /**
     * Index of the certificate producing the highest expiration risk.
     */
    val highestRiskIndex: Int?
)
