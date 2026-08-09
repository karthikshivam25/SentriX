package com.sentrix.security.rootdetection

/**
 * RootDetectionResult
 *
 * Canonical result model representing the outcome of a SentriX
 * root-detection operation.
 *
 * This class is intentionally a data model.
 *
 * It does NOT perform:
 * - root detection
 * - filesystem inspection
 * - command execution
 * - package inspection
 * - risk calculation
 *
 * Those responsibilities belong to the corresponding security
 * components.
 *
 * Architecture:
 *
 * RootDetectionService
 *        ↓
 * RootDetectionManager
 *        ↓
 * RootChecker / Specialized Checkers
 *        ↓
 * RootDetectionValidator
 *        ↓
 * RootDetectionResult
 *        ↓
 * Security Report / UI / Repository
 *
 * The result is immutable so that once a security decision has
 * been produced, consumers cannot accidentally modify the result.
 */
data class RootDetectionResult(

    /**
     * Final root-detection state.
     */
    val status: RootDetectionStatus,

    /**
     * Overall root-detection risk score.
     *
     * Range:
     *
     * 0   = minimal detected risk
     * 100 = maximum detected risk
     */
    val riskScore: Int,

    /**
     * Confidence in the final root-detection assessment.
     *
     * Range:
     *
     * 0.0 = very low confidence
     * 1.0 = very high confidence
     *
     * This is confidence in the assessment, not probability that
     * the device is rooted.
     */
    val confidence: Double,

    /**
     * Individual root-detection indicators.
     */
    val indicators: List<RootDetectionIndicator>,

    /**
     * Detailed root evidence collected from the device.
     */
    val evidence: List<RootDetectionEvidence>,

    /**
     * Summary of the checks performed.
     */
    val checkSummary: RootDetectionCheckSummary,

    /**
     * Device information captured at detection time.
     */
    val deviceInfo: RootDetectionDeviceInfo,

    /**
     * Timestamp at which the detection completed.
     */
    val detectedAt: Long,

    /**
     * Unique identifier for this detection operation.
     *
     * This can later be used to correlate:
     *
     * - local database records
     * - security reports
     * - analytics
     * - threat events
     * - telemetry
     */
    val detectionId: String,

    /**
     * Whether the detection operation completed successfully.
     *
     * A false value means the result should be interpreted as
     * incomplete rather than automatically secure or rooted.
     */
    val detectionCompleted: Boolean,

    /**
     * Optional error information.
     *
     * Should contain safe, non-sensitive diagnostic information.
     */
    val error: RootDetectionError? = null
) {

    /**
     * Returns true when the final assessment indicates that
     * root compromise is confirmed or highly suspected.
     */
    val isRootDetected: Boolean
        get() = status == RootDetectionStatus.ROOT_DETECTED ||
                status == RootDetectionStatus.ROOT_HIGH_CONFIDENCE

    /**
     * Returns true when strong root evidence exists.
     */
    val hasStrongEvidence: Boolean
        get() = indicators.any {
            it.severity == RootIndicatorSeverity.HIGH ||
                    it.severity == RootIndicatorSeverity.CRITICAL
        }

    /**
     * Returns true when the result indicates an elevated
     * device-integrity concern.
     */
    val hasSecurityConcern: Boolean
        get() = status != RootDetectionStatus.SECURE &&
                status != RootDetectionStatus.NOT_DETECTED

    /**
     * Returns true when the detection result is usable.
     */
    val isValidResult: Boolean
        get() = detectionCompleted &&
                error == null

    /**
     * Returns the number of collected indicators.
     */
    val indicatorCount: Int
        get() = indicators.size

    /**
     * Returns the number of collected evidence items.
     */
    val evidenceCount: Int
        get() = evidence.size

    /**
     * Returns the highest indicator severity.
     */
    val highestSeverity: RootIndicatorSeverity
        get() {

            return indicators
                .maxByOrNull {
                    severityWeight(it.severity)
                }
                ?.severity
                ?: RootIndicatorSeverity.INFO
        }

    /**
     * Returns the risk classification associated with the score.
     */
    val riskLevel: RootDetectionRiskLevel
        get() {

            return when {

                riskScore >= 80 ->
                    RootDetectionRiskLevel.CRITICAL

                riskScore >= 60 ->
                    RootDetectionRiskLevel.HIGH

                riskScore >= 30 ->
                    RootDetectionRiskLevel.MEDIUM

                riskScore > 0 ->
                    RootDetectionRiskLevel.LOW

                else ->
                    RootDetectionRiskLevel.NONE
            }
        }

    /**
     * Returns a short machine-readable classification.
     */
    fun getClassification(): String {

        return when (status) {

            RootDetectionStatus.SECURE ->
                "SECURE"

            RootDetectionStatus.NOT_DETECTED ->
                "ROOT_NOT_DETECTED"

            RootDetectionStatus.SUSPICIOUS ->
                "SUSPICIOUS"

            RootDetectionStatus.ROOT_HIGH_CONFIDENCE ->
                "ROOT_HIGH_CONFIDENCE"

            RootDetectionStatus.ROOT_DETECTED ->
                "ROOT_DETECTED"

            RootDetectionStatus.CHECK_FAILED ->
                "CHECK_FAILED"

            RootDetectionStatus.CHECK_INCOMPLETE ->
                "CHECK_INCOMPLETE"
        }
    }

    /**
     * Returns a user-safe summary.
     *
     * Detailed technical evidence should be presented separately
     * when appropriate.
     */
    fun getUserSafeSummary(): String {

        return when (status) {

            RootDetectionStatus.SECURE ->
                "No significant device integrity concerns were detected."

            RootDetectionStatus.NOT_DETECTED ->
                "No root indicators were detected."

            RootDetectionStatus.SUSPICIOUS ->
                "Potential device integrity concerns were detected."

            RootDetectionStatus.ROOT_HIGH_CONFIDENCE ->
                "Strong indicators of elevated device privileges were detected."

            RootDetectionStatus.ROOT_DETECTED ->
                "Root-related activity or configuration was detected."

            RootDetectionStatus.CHECK_FAILED ->
                "The device integrity check could not be completed."

            RootDetectionStatus.CHECK_INCOMPLETE ->
                "The device integrity check was incomplete."
        }
    }

    /**
     * Returns only high and critical indicators.
     */
    fun getCriticalIndicators():
            List<RootDetectionIndicator> {

        return indicators.filter {
            it.severity == RootIndicatorSeverity.HIGH ||
                    it.severity == RootIndicatorSeverity.CRITICAL
        }
    }

    /**
     * Returns a copy with an updated risk score.
     *
     * Useful for immutable transformations inside the domain layer.
     */
    fun withRiskScore(
        newRiskScore: Int
    ): RootDetectionResult {

        return copy(
            riskScore = newRiskScore.coerceIn(0, 100)
        )
    }

    /**
     * Returns a copy with additional indicators.
     */
    fun withIndicators(
        additionalIndicators:
        List<RootDetectionIndicator>
    ): RootDetectionResult {

        return copy(
            indicators = indicators + additionalIndicators
        )
    }

    /**
     * Returns a copy with additional evidence.
     */
    fun withEvidence(
        additionalEvidence:
        List<RootDetectionEvidence>
    ): RootDetectionResult {

        return copy(
            evidence = evidence + additionalEvidence
        )
    }

    /**
     * Converts severity to a sortable weight.
     */
    private fun severityWeight(
        severity: RootIndicatorSeverity
    ): Int {

        return when (severity) {

            RootIndicatorSeverity.INFO -> 0

            RootIndicatorSeverity.LOW -> 1

            RootIndicatorSeverity.MEDIUM -> 2

            RootIndicatorSeverity.HIGH -> 3

            RootIndicatorSeverity.CRITICAL -> 4
        }
    }

    companion object {

        /**
         * Creates a secure result.
         */
        fun secure(
            detectionId: String,
            deviceInfo: RootDetectionDeviceInfo,
            checkSummary: RootDetectionCheckSummary,
            evidence: List<RootDetectionEvidence> = emptyList(),
            indicators: List<RootDetectionIndicator> = emptyList()
        ): RootDetectionResult {

            return RootDetectionResult(
                status = RootDetectionStatus.SECURE,
                riskScore = 0,
                confidence = 1.0,
                indicators = indicators,
                evidence = evidence,
                checkSummary = checkSummary,
                deviceInfo = deviceInfo,
                detectedAt = System.currentTimeMillis(),
                detectionId = detectionId,
                detectionCompleted = true
            )
        }

        /**
         * Creates a failed detection result.
         */
        fun failed(
            detectionId: String,
            deviceInfo: RootDetectionDeviceInfo,
            checkSummary: RootDetectionCheckSummary,
            error: RootDetectionError
        ): RootDetectionResult {

            return RootDetectionResult(
                status = RootDetectionStatus.CHECK_FAILED,
                riskScore = 0,
                confidence = 0.0,
                indicators = emptyList(),
                evidence = emptyList(),
                checkSummary = checkSummary,
                deviceInfo = deviceInfo,
                detectedAt = System.currentTimeMillis(),
                detectionId = detectionId,
                detectionCompleted = false,
                error = error
            )
        }
    }
}

/**
 * Final classification produced by the root-detection validator.
 */
enum class RootDetectionStatus {

    /**
     * No significant security concerns were found.
     */
    SECURE,

    /**
     * No root indicators were observed.
     *
     * This differs from SECURE because the check may be limited
     * or the available evidence may not be sufficient to establish
     * a strong security conclusion.
     */
    NOT_DETECTED,

    /**
     * Some suspicious indicators exist but are insufficient for
     * a high-confidence root determination.
     */
    SUSPICIOUS,

    /**
     * Multiple strong signals indicate a high-confidence root
     * environment.
     */
    ROOT_HIGH_CONFIDENCE,

    /**
     * Root-related activity/configuration has been detected.
     */
    ROOT_DETECTED,

    /**
     * Detection encountered an operational failure.
     */
    CHECK_FAILED,

    /**
     * Detection completed only partially.
     */
    CHECK_INCOMPLETE
}

/**
 * Overall risk classification.
 */
enum class RootDetectionRiskLevel {

    /**
     * No detected root-related risk.
     */
    NONE,

    /**
     * Low-level indicators.
     */
    LOW,

    /**
     * Moderate indicators.
     */
    MEDIUM,

    /**
     * Strong indicators.
     */
    HIGH,

    /**
     * Severe device-integrity concern.
     */
    CRITICAL
}

/**
 * Summary of checks performed during root detection.
 */
data class RootDetectionCheckSummary(

    /**
     * Whether root-binary checks were executed.
     */
    val binaryCheckPerformed: Boolean,

    /**
     * Whether root-package checks were executed.
     */
    val packageCheckPerformed: Boolean,

    /**
     * Whether system-property checks were executed.
     */
    val propertyCheckPerformed: Boolean,

    /**
     * Whether command-based checks were executed.
     */
    val commandCheckPerformed: Boolean,

    /**
     * Whether environment checks were executed.
     */
    val environmentCheckPerformed: Boolean,

    /**
     * Whether evidence aggregation was performed.
     */
    val evidenceCollectionPerformed: Boolean,

    /**
     * Total number of logical checks attempted.
     */
    val totalChecks: Int,

    /**
     * Number of checks that completed successfully.
     */
    val successfulChecks: Int,

    /**
     * Number of checks that failed.
     */
    val failedChecks: Int
) {

    /**
     * Returns true when every expected check completed.
     */
    val allChecksCompleted: Boolean
        get() = totalChecks > 0 &&
                failedChecks == 0 &&
                successfulChecks >= totalChecks

    /**
     * Returns completion percentage.
     */
    val completionPercentage: Int
        get() {

            if (totalChecks <= 0) {
                return 0
            }

            return (
                successfulChecks
                    .toDouble()
                    .div(totalChecks.toDouble())
                    .times(100.0)
                    .toInt()
            ).coerceIn(0, 100)
        }
}

/**
 * Device information captured when the root-detection result
 * was produced.
 *
 * Only security-relevant metadata should be stored here.
 */
data class RootDetectionDeviceInfo(

    /**
     * Device manufacturer.
     */
    val manufacturer: String,

    /**
     * Device model.
     */
    val model: String,

    /**
     * Android release.
     */
    val androidVersion: String,

    /**
     * Android API level.
     */
    val sdkVersion: Int,

    /**
     * Build type, when available.
     */
    val buildType: String?,

    /**
     * Build tags, when available.
     */
    val buildTags: String?,

    /**
     * Whether the application process was running under UID 0.
     */
    val processRunningAsRoot: Boolean
)

/**
 * Generic structured evidence used by RootDetectionResult.
 *
 * This allows the result model to combine evidence originating
 * from different specialized checkers without coupling the result
 * to any one checker implementation.
 */
data class RootDetectionEvidence(

    /**
     * Evidence source category.
     */
    val source: RootEvidenceSource,

    /**
     * Short evidence identifier.
     */
    val identifier: String,

    /**
     * Human-readable explanation.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String?,

    /**
     * Evidence severity.
     */
    val severity: RootIndicatorSeverity,

    /**
     * Confidence in the evidence observation.
     *
     * This is not root probability.
     */
    val confidence: Double
)

/**
 * Source of root-detection evidence.
 */
enum class RootEvidenceSource {

    /**
     * Root binary checker.
     */
    BINARY,

    /**
     * Root package checker.
     */
    PACKAGE,

    /**
     * System-property checker.
     */
    PROPERTY,

    /**
     * Command checker.
     */
    COMMAND,

    /**
     * Environment checker.
     */
    ENVIRONMENT,

    /**
     * Evidence generated from correlation of multiple signals.
     */
    CORRELATION,

    /**
     * External device-integrity/attestation signal.
     */
    ATTESTATION
}

/**
 * Error information associated with an incomplete or failed
 * detection operation.
 */
data class RootDetectionError(

    /**
     * Machine-readable error code.
     */
    val code: RootDetectionErrorCode,

    /**
     * Safe human-readable description.
     */
    val message: String,

    /**
     * Optional technical category.
     */
    val category: String? = null
)

/**
 * Root-detection failure categories.
 */
enum class RootDetectionErrorCode {

    /**
     * A required component was unavailable.
     */
    COMPONENT_UNAVAILABLE,

    /**
     * Android denied an operation.
     */
    SECURITY_EXCEPTION,

    /**
     * A command timed out.
     */
    COMMAND_TIMEOUT,

    /**
     * Filesystem access failed.
     */
    FILESYSTEM_ACCESS_FAILED,

    /**
     * Package information could not be obtained.
     */
    PACKAGE_ACCESS_FAILED,

    /**
     * System-property access failed.
     */
    PROPERTY_ACCESS_FAILED,

    /**
     * Unexpected internal error.
     */
    INTERNAL_ERROR,

    /**
     * Detection could not finish.
     */
    INCOMPLETE_SCAN
}
