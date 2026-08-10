package com.sentrix.security.antitamper

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * TamperReportGenerator
 *
 * Generates a consolidated anti-tamper report from the results
 * produced by SentriX tamper detectors.
 *
 * Responsibilities:
 *
 * - Aggregate results from multiple tamper detectors.
 * - Normalize detector evidence.
 * - Calculate an overall tamper risk score.
 * - Determine the highest observed severity.
 * - Identify critical findings.
 * - Generate recommendations.
 * - Generate a human-readable report.
 * - Provide structured report data for UI/API/storage.
 *
 * Detectors that can contribute:
 *
 * - AppTamperDetector
 * - CodeTamperDetector
 * - ResourceTamperDetector
 * - SignatureTamperDetector
 * - PackageTamperDetector
 * - RuntimeTamperDetector
 *
 * This class does NOT:
 *
 * - modify the application
 * - terminate processes
 * - remove files
 * - block the user
 * - execute commands
 *
 * It is a reporting and risk-correlation component.
 *
 * Architecture:
 *
 * Individual Detectors
 *        ↓
 * Detector Results
 *        ↓
 * TamperReportGenerator
 *        ↓
 * TamperReport
 *        ↓
 * AntiTamperValidator
 *        ↓
 * SentriX Security Engine
 */
class TamperReportGenerator(
    private val context: Context
) {

    /**
     * Date format used by human-readable reports.
     */
    private val dateFormat =
        SimpleDateFormat(
            REPORT_DATE_PATTERN,
            Locale.US
        )

    /**
     * Generates a complete consolidated report.
     *
     * Any detector result can be null when that particular
     * detector was not executed.
     */
    fun generateReport(
        appTamperResult: AppTamperResult? = null,
        codeTamperResult: CodeTamperResult? = null,
        resourceTamperResult: ResourceTamperResult? = null,
        signatureTamperResult: SignatureTamperResult? = null,
        packageTamperResult: PackageTamperResult? = null,
        runtimeTamperResult: RuntimeTamperResult? = null
    ): TamperReport {

        val generatedAt =
            System.currentTimeMillis()

        /**
         * ---------------------------------------------------------
         * Aggregate evidence
         * ---------------------------------------------------------
         */
        val findings =
            mutableListOf<TamperFinding>()

        collectAppTamperFindings(
            result = appTamperResult,
            findings = findings
        )

        collectCodeTamperFindings(
            result = codeTamperResult,
            findings = findings
        )

        collectResourceTamperFindings(
            result = resourceTamperResult,
            findings = findings
        )

        collectSignatureTamperFindings(
            result = signatureTamperResult,
            findings = findings
        )

        collectPackageTamperFindings(
            result = packageTamperResult,
            findings = findings
        )

        collectRuntimeTamperFindings(
            result = runtimeTamperResult,
            findings = findings
        )

        /**
         * ---------------------------------------------------------
         * Calculate score
         * ---------------------------------------------------------
         */
        val riskScore =
            calculateRiskScore(
                findings
            )

        /**
         * ---------------------------------------------------------
         * Determine severity
         * ---------------------------------------------------------
         */
        val severity =
            determineOverallSeverity(
                findings = findings,
                riskScore = riskScore
            )

        /**
         * ---------------------------------------------------------
         * Determine overall status
         * ---------------------------------------------------------
         */
        val status =
            determineOverallStatus(
                findings = findings,
                riskScore = riskScore
            )

        /**
         * ---------------------------------------------------------
         * Critical findings
         * ---------------------------------------------------------
         */
        val criticalFindings =
            findings.filter {
                it.severity ==
                        TamperFindingSeverity.CRITICAL
            }

        /**
         * ---------------------------------------------------------
         * Recommendations
         * ---------------------------------------------------------
         */
        val recommendations =
            generateRecommendations(
                findings = findings,
                status = status
            )

        /**
         * ---------------------------------------------------------
         * Detector execution summary
         * ---------------------------------------------------------
         */
        val detectorSummary =
            createDetectorSummary(
                appTamperResult = appTamperResult,
                codeTamperResult = codeTamperResult,
                resourceTamperResult = resourceTamperResult,
                signatureTamperResult = signatureTamperResult,
                packageTamperResult = packageTamperResult,
                runtimeTamperResult = runtimeTamperResult
            )

        return TamperReport(
            reportId =
                generateReportId(
                    generatedAt
                ),
            packageName =
                context.packageName,
            generatedAt = generatedAt,
            status = status,
            severity = severity,
            riskScore = riskScore,
            findings = findings,
            criticalFindings = criticalFindings,
            recommendations = recommendations,
            detectorSummary = detectorSummary,
            detectionCoverage =
                calculateDetectionCoverage(
                    detectorSummary
                )
        )
    }

    /**
     * Generates a concise report from already available findings.
     */
    fun generateReportFromFindings(
        findings: List<TamperFinding>
    ): TamperReport {

        val riskScore =
            calculateRiskScore(
                findings
            )

        val severity =
            determineOverallSeverity(
                findings = findings,
                riskScore = riskScore
            )

        val status =
            determineOverallStatus(
                findings = findings,
                riskScore = riskScore
            )

        val criticalFindings =
            findings.filter {
                it.severity ==
                        TamperFindingSeverity.CRITICAL
            }

        return TamperReport(
            reportId =
                generateReportId(
                    System.currentTimeMillis()
                ),
            packageName =
                context.packageName,
            generatedAt =
                System.currentTimeMillis(),
            status = status,
            severity = severity,
            riskScore = riskScore,
            findings = findings,
            criticalFindings = criticalFindings,
            recommendations =
                generateRecommendations(
                    findings,
                    status
                ),
            detectorSummary =
                TamperDetectorSummary(),
            detectionCoverage = 0
        )
    }

    /**
     * Collects AppTamperDetector findings.
     */
    private fun collectAppTamperFindings(
        result: AppTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapAppSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.APPLICATION,
                source = "AppTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Collects CodeTamperDetector findings.
     */
    private fun collectCodeTamperFindings(
        result: CodeTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapCodeSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.CODE,
                source = "CodeTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                path = evidence.path,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Collects ResourceTamperDetector findings.
     */
    private fun collectResourceTamperFindings(
        result: ResourceTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapResourceSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.RESOURCE,
                source = "ResourceTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                path = evidence.resourcePath,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Collects SignatureTamperDetector findings.
     */
    private fun collectSignatureTamperFindings(
        result: SignatureTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapSignatureSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.SIGNATURE,
                source = "SignatureTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Collects PackageTamperDetector findings.
     */
    private fun collectPackageTamperFindings(
        result: PackageTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapPackageSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.PACKAGE,
                source = "PackageTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Collects RuntimeTamperDetector findings.
     */
    private fun collectRuntimeTamperFindings(
        result: RuntimeTamperResult?,
        findings: MutableList<TamperFinding>
    ) {

        result ?: return

        result.evidence.forEach { evidence ->

            val severity =
                mapRuntimeSeverity(
                    evidence.severity
                )

            findings += TamperFinding(
                category =
                    TamperFindingCategory.RUNTIME,
                source = "RuntimeTamperDetector",
                type = evidence.type.name,
                title =
                    createTitle(
                        evidence.type.name
                    ),
                description =
                    evidence.description,
                value = evidence.value,
                expectedValue =
                    evidence.expectedValue,
                severity = severity,
                confidence =
                    normalizeConfidence(
                        evidence.confidence
                    )
            )
        }
    }

    /**
     * Calculates the overall risk score.
     *
     * Score range:
     *
     * 0   → No significant risk
     * 1-24 → Low
     * 25-49 → Moderate
     * 50-74 → High
     * 75-100 → Critical
     *
     * Evidence confidence is incorporated into the calculation.
     */
    private fun calculateRiskScore(
        findings: List<TamperFinding>
    ): Int {

        if (findings.isEmpty()) {
            return 0
        }

        var totalScore = 0.0

        findings.forEach { finding ->

            val severityWeight =
                when (finding.severity) {

                    TamperFindingSeverity.INFO ->
                        0.0

                    TamperFindingSeverity.LOW ->
                        5.0

                    TamperFindingSeverity.MEDIUM ->
                        15.0

                    TamperFindingSeverity.HIGH ->
                        30.0

                    TamperFindingSeverity.CRITICAL ->
                        50.0
                }

            val confidence =
                finding.confidence
                    .coerceIn(
                        0.0,
                        1.0
                    )

            totalScore +=
                severityWeight *
                        confidence
        }

        /**
         * Multiple findings from the same detector should not
         * inflate the score without limit.
         */
        val categoryBonus =
            calculateCategoryBonus(
                findings
            )

        totalScore +=
            categoryBonus

        return totalScore
            .coerceIn(
                0.0,
                100.0
            )
            .toInt()
    }

    /**
     * Adds a modest bonus when independent detector categories
     * agree on suspicious activity.
     *
     * This rewards cross-signal correlation without making the
     * score completely dependent on a single detector.
     */
    private fun calculateCategoryBonus(
        findings: List<TamperFinding>
    ): Double {

        val suspiciousCategories =
            findings
                .filter {
                    it.severity ==
                            TamperFindingSeverity.MEDIUM ||
                            it.severity ==
                            TamperFindingSeverity.HIGH ||
                            it.severity ==
                            TamperFindingSeverity.CRITICAL
                }
                .map {
                    it.category
                }
                .distinct()

        return when {

            suspiciousCategories.size >= 5 ->
                15.0

            suspiciousCategories.size >= 4 ->
                10.0

            suspiciousCategories.size >= 3 ->
                7.0

            suspiciousCategories.size >= 2 ->
                4.0

            else ->
                0.0
        }
    }

    /**
     * Determines overall severity.
     */
    private fun determineOverallSeverity(
        findings: List<TamperFinding>,
        riskScore: Int
    ): TamperFindingSeverity {

        /**
         * A confirmed signature/code/resource mismatch should
         * remain critical regardless of aggregate score.
         */
        if (
            findings.any {
                it.severity ==
                        TamperFindingSeverity.CRITICAL &&
                        (
                            it.category ==
                                    TamperFindingCategory.SIGNATURE ||
                                    it.category ==
                                    TamperFindingCategory.CODE ||
                                    it.category ==
                                    TamperFindingCategory.RESOURCE
                        )
            }
        ) {

            return TamperFindingSeverity.CRITICAL
        }

        return when {

            riskScore >= 75 ->
                TamperFindingSeverity.CRITICAL

            riskScore >= 50 ->
                TamperFindingSeverity.HIGH

            riskScore >= 25 ->
                TamperFindingSeverity.MEDIUM

            riskScore > 0 ->
                TamperFindingSeverity.LOW

            else ->
                TamperFindingSeverity.INFO
        }
    }

    /**
     * Determines the overall report status.
     */
    private fun determineOverallStatus(
        findings: List<TamperFinding>,
        riskScore: Int
    ): TamperReportStatus {

        val confirmedIntegrityFailure =
            findings.any {
                it.severity ==
                        TamperFindingSeverity.CRITICAL &&
                        (
                            it.category ==
                                    TamperFindingCategory.SIGNATURE ||
                                    it.category ==
                                    TamperFindingCategory.CODE ||
                                    it.category ==
                                    TamperFindingCategory.RESOURCE
                        )
            }

        if (confirmedIntegrityFailure) {

            return TamperReportStatus.TAMPER_DETECTED
        }

        return when {

            riskScore >= 75 ->
                TamperReportStatus.CRITICAL_RISK

            riskScore >= 50 ->
                TamperReportStatus.HIGH_RISK

            riskScore >= 25 ->
                TamperReportStatus.SUSPICIOUS

            riskScore > 0 ->
                TamperReportStatus.LOW_RISK

            else ->
                TamperReportStatus.NO_TAMPER_DETECTED
        }
    }

    /**
     * Generates recommendations based on the collected evidence.
     */
    private fun generateRecommendations(
        findings: List<TamperFinding>,
        status: TamperReportStatus
    ): List<TamperRecommendation> {

        val recommendations =
            mutableListOf<TamperRecommendation>()

        val signatureMismatch =
            findings.any {
                it.category ==
                        TamperFindingCategory.SIGNATURE &&
                        it.severity ==
                        TamperFindingSeverity.CRITICAL
            }

        val codeMismatch =
            findings.any {
                it.category ==
                        TamperFindingCategory.CODE &&
                        it.severity ==
                        TamperFindingSeverity.CRITICAL
            }

        val resourceMismatch =
            findings.any {
                it.category ==
                        TamperFindingCategory.RESOURCE &&
                        it.severity ==
                        TamperFindingSeverity.CRITICAL
            }

        val packageMismatch =
            findings.any {
                it.category ==
                        TamperFindingCategory.PACKAGE &&
                        (
                            it.severity ==
                                    TamperFindingSeverity.HIGH ||
                                    it.severity ==
                                    TamperFindingSeverity.CRITICAL
                        )
            }

        val runtimeSuspicious =
            findings.any {
                it.category ==
                        TamperFindingCategory.RUNTIME &&
                        (
                            it.severity ==
                                    TamperFindingSeverity.HIGH ||
                                    it.severity ==
                                    TamperFindingSeverity.CRITICAL
                        )
            }

        /**
         * Signature recommendation.
         */
        if (signatureMismatch) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.CRITICAL,
                title =
                    "Verify application signing identity",
                description =
                    "The installed application's signing identity does not match the trusted certificate set.",
                action =
                    "Reinstall the application from a trusted distribution source and verify the release signing configuration."
            )
        }

        /**
         * Code recommendation.
         */
        if (codeMismatch) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.CRITICAL,
                title =
                    "Verify application code integrity",
                description =
                    "One or more trusted APK/DEX hashes do not match the installed application.",
                action =
                    "Reinstall a trusted application build and perform a complete integrity verification."
            )
        }

        /**
         * Resource recommendation.
         */
        if (resourceMismatch) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.HIGH,
                title =
                    "Verify application resources",
                description =
                    "One or more protected resources differ from trusted integrity values.",
                action =
                    "Reinstall the trusted application package and repeat resource integrity validation."
            )
        }

        /**
         * Package recommendation.
         */
        if (packageMismatch) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.HIGH,
                title =
                    "Verify application installation",
                description =
                    "Package metadata contains a significant integrity inconsistency.",
                action =
                    "Verify the installed package and reinstall it from a trusted source if necessary."
            )
        }

        /**
         * Runtime recommendation.
         */
        if (runtimeSuspicious) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.MEDIUM,
                title =
                    "Review runtime environment",
                description =
                    "The application runtime contains suspicious integrity indicators.",
                action =
                    "Review debugging, instrumentation, class-loader, and runtime configuration before trusting the process."
            )
        }

        /**
         * General high-risk recommendation.
         */
        if (
            status ==
                    TamperReportStatus.CRITICAL_RISK ||
                    status ==
                    TamperReportStatus.TAMPER_DETECTED
        ) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.CRITICAL,
                title =
                    "Restrict sensitive operations",
                description =
                    "The combined integrity evidence indicates elevated application security risk.",
                action =
                    "Allow AntiTamperValidator to determine whether sensitive operations should require additional verification."
            )
        }

        /**
         * No significant findings.
         */
        if (recommendations.isEmpty()) {

            recommendations += TamperRecommendation(
                priority =
                    TamperRecommendationPriority.INFO,
                title =
                    "No immediate action required",
                description =
                    "No significant tamper indicators were identified by the executed detectors.",
                action =
                    "Continue normal SentriX integrity monitoring."
            )
        }

        return recommendations
    }

    /**
     * Creates detector execution summary.
     */
    private fun createDetectorSummary(
        appTamperResult: AppTamperResult?,
        codeTamperResult: CodeTamperResult?,
        resourceTamperResult: ResourceTamperResult?,
        signatureTamperResult: SignatureTamperResult?,
        packageTamperResult: PackageTamperResult?,
        runtimeTamperResult: RuntimeTamperResult?
    ): TamperDetectorSummary {

        return TamperDetectorSummary(
            appDetectorExecuted =
                appTamperResult != null,

            appDetectorCompleted =
                appTamperResult?.detectionCompleted
                    ?: false,

            codeDetectorExecuted =
                codeTamperResult != null,

            codeDetectorCompleted =
                codeTamperResult?.detectionCompleted
                    ?: false,

            resourceDetectorExecuted =
                resourceTamperResult != null,

            resourceDetectorCompleted =
                resourceTamperResult?.detectionCompleted
                    ?: false,

            signatureDetectorExecuted =
                signatureTamperResult != null,

            signatureDetectorCompleted =
                signatureTamperResult?.detectionCompleted
                    ?: false,

            packageDetectorExecuted =
                packageTamperResult != null,

            packageDetectorCompleted =
                packageTamperResult?.detectionCompleted
                    ?: false,

            runtimeDetectorExecuted =
                runtimeTamperResult != null,

            runtimeDetectorCompleted =
                runtimeTamperResult?.detectionCompleted
                    ?: false
        )
    }

    /**
     * Calculates how much of the configured detector surface
     * was actually executed.
     */
    private fun calculateDetectionCoverage(
        summary: TamperDetectorSummary
    ): Int {

        val executed =
            listOf(
                summary.appDetectorExecuted,
                summary.codeDetectorExecuted,
                summary.resourceDetectorExecuted,
                summary.signatureDetectorExecuted,
                summary.packageDetectorExecuted,
                summary.runtimeDetectorExecuted
            ).count {
                it
            }

        val total =
            6

        if (total == 0) {
            return 0
        }

        return (
            executed.toDouble() /
                    total.toDouble() *
                    100.0
            )
            .toInt()
            .coerceIn(0, 100)
    }

    /**
     * Converts AppTamper severity.
     */
    private fun mapAppSeverity(
        severity: AppTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            AppTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            AppTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            AppTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            AppTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            AppTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Converts CodeTamper severity.
     */
    private fun mapCodeSeverity(
        severity: CodeTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            CodeTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            CodeTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            CodeTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            CodeTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            CodeTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Converts ResourceTamper severity.
     */
    private fun mapResourceSeverity(
        severity: ResourceTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            ResourceTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            ResourceTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            ResourceTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            ResourceTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            ResourceTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Converts SignatureTamper severity.
     */
    private fun mapSignatureSeverity(
        severity: SignatureTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            SignatureTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            SignatureTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            SignatureTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            SignatureTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            SignatureTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Converts PackageTamper severity.
     */
    private fun mapPackageSeverity(
        severity: PackageTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            PackageTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            PackageTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            PackageTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            PackageTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            PackageTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Converts RuntimeTamper severity.
     */
    private fun mapRuntimeSeverity(
        severity: RuntimeTamperSeverity
    ): TamperFindingSeverity {

        return when (severity) {

            RuntimeTamperSeverity.INFO ->
                TamperFindingSeverity.INFO

            RuntimeTamperSeverity.LOW ->
                TamperFindingSeverity.LOW

            RuntimeTamperSeverity.MEDIUM ->
                TamperFindingSeverity.MEDIUM

            RuntimeTamperSeverity.HIGH ->
                TamperFindingSeverity.HIGH

            RuntimeTamperSeverity.CRITICAL ->
                TamperFindingSeverity.CRITICAL
        }
    }

    /**
     * Keeps confidence inside the valid range.
     */
    private fun normalizeConfidence(
        confidence: Double
    ): Double {

        return confidence.coerceIn(
            0.0,
            1.0
        )
    }

    /**
     * Converts enum-style names into readable titles.
     */
    private fun createTitle(
        rawType: String
    ): String {

        return rawType
            .lowercase(Locale.US)
            .split("_")
            .joinToString(" ") { word ->

                word.replaceFirstChar {
                    if (it.isLowerCase()) {
                        it.titlecase(Locale.US)
                    } else {
                        it.toString()
                    }
                }
            }
    }

    /**
     * Creates a unique report identifier.
     */
    private fun generateReportId(
        timestamp: Long
    ): String {

        return "TAMPER-" +
                timestamp.toString(36)
                    .uppercase(Locale.US)
    }

    /**
     * Converts timestamp to human-readable format.
     */
    fun formatTimestamp(
        timestamp: Long
    ): String {

        return dateFormat.format(
            Date(timestamp)
        )
    }

    companion object {

        /**
         * Standard report timestamp pattern.
         */
        private const val REPORT_DATE_PATTERN =
            "yyyy-MM-dd HH:mm:ss"
    }
}

/**
 * Consolidated SentriX anti-tamper report.
 */
data class TamperReport(

    /**
     * Unique report identifier.
     */
    val reportId: String,

    /**
     * Application package.
     */
    val packageName: String,

    /**
     * Report creation timestamp.
     */
    val generatedAt: Long,

    /**
     * Overall report status.
     */
    val status: TamperReportStatus,

    /**
     * Overall severity.
     */
    val severity: TamperFindingSeverity,

    /**
     * Overall normalized risk score.
     *
     * Range: 0-100.
     */
    val riskScore: Int,

    /**
     * All aggregated findings.
     */
    val findings: List<TamperFinding>,

    /**
     * Critical findings only.
     */
    val criticalFindings: List<TamperFinding>,

    /**
     * Recommended actions.
     */
    val recommendations: List<TamperRecommendation>,

    /**
     * Detector execution summary.
     */
    val detectorSummary: TamperDetectorSummary,

    /**
     * Percentage of configured detectors that were executed.
     */
    val detectionCoverage: Int
) {

    /**
     * True when tampering is detected.
     */
    val isTampered: Boolean
        get() =
            status ==
                    TamperReportStatus.TAMPER_DETECTED

    /**
     * True when report indicates significant risk.
     */
    val isHighRisk: Boolean
        get() =
            riskScore >= 50

    /**
     * Number of findings.
     */
    val findingCount: Int
        get() =
            findings.size

    /**
     * Number of critical findings.
     */
    val criticalFindingCount: Int
        get() =
            criticalFindings.size

    /**
     * Human-readable status.
     */
    fun getStatusDescription(): String {

        return when (status) {

            TamperReportStatus.NO_TAMPER_DETECTED ->
                "No significant tampering indicators detected."

            TamperReportStatus.LOW_RISK ->
                "Low-level integrity risk detected."

            TamperReportStatus.SUSPICIOUS ->
                "Suspicious application integrity indicators detected."

            TamperReportStatus.HIGH_RISK ->
                "High application integrity risk detected."

            TamperReportStatus.CRITICAL_RISK ->
                "Critical application integrity risk detected."

            TamperReportStatus.TAMPER_DETECTED ->
                "Application tampering has been detected."
        }
    }
}

/**
 * Consolidated tamper finding.
 */
data class TamperFinding(

    /**
     * Detector category.
     */
    val category: TamperFindingCategory,

    /**
     * Detector that produced the finding.
     */
    val source: String,

    /**
     * Original detector evidence type.
     */
    val type: String,

    /**
     * Human-readable finding title.
     */
    val title: String,

    /**
     * Finding description.
     */
    val description: String,

    /**
     * Observed value.
     */
    val value: String? = null,

    /**
     * Expected value.
     */
    val expectedValue: String? = null,

    /**
     * Associated path.
     */
    val path: String? = null,

    /**
     * Normalized severity.
     */
    val severity: TamperFindingSeverity,

    /**
     * Confidence.
     */
    val confidence: Double
)

/**
 * Tamper finding categories.
 */
enum class TamperFindingCategory {

    /**
     * Application identity/configuration.
     */
    APPLICATION,

    /**
     * Compiled code.
     */
    CODE,

    /**
     * Packaged resources.
     */
    RESOURCE,

    /**
     * Signing identity.
     */
    SIGNATURE,

    /**
     * Android package/install metadata.
     */
    PACKAGE,

    /**
     * Runtime execution environment.
     */
    RUNTIME
}

/**
 * Normalized tamper severity.
 */
enum class TamperFindingSeverity {

    /**
     * Informational.
     */
    INFO,

    /**
     * Low risk.
     */
    LOW,

    /**
     * Moderate risk.
     */
    MEDIUM,

    /**
     * High risk.
     */
    HIGH,

    /**
     * Critical risk.
     */
    CRITICAL
}

/**
 * Overall tamper report status.
 */
enum class TamperReportStatus {

    /**
     * No significant tampering indicators.
     */
    NO_TAMPER_DETECTED,

    /**
     * Low risk.
     */
    LOW_RISK,

    /**
     * Suspicious evidence.
     */
    SUSPICIOUS,

    /**
     * High risk.
     */
    HIGH_RISK,

    /**
     * Critical risk.
     */
    CRITICAL_RISK,

    /**
     * Strong integrity mismatch detected.
     */
    TAMPER_DETECTED
}

/**
 * Recommended action generated from tamper findings.
 */
data class TamperRecommendation(

    /**
     * Recommendation priority.
     */
    val priority: TamperRecommendationPriority,

    /**
     * Recommendation title.
     */
    val title: String,

    /**
     * Explanation.
     */
    val description: String,

    /**
     * Suggested action.
     */
    val action: String
)

/**
 * Tamper recommendation priority.
 */
enum class TamperRecommendationPriority {

    /**
     * Informational.
     */
    INFO,

    /**
     * Medium priority.
     */
    MEDIUM,

    /**
     * High priority.
     */
    HIGH,

    /**
     * Critical priority.
     */
    CRITICAL
}

/**
 * Detector execution summary.
 */
data class TamperDetectorSummary(

    /**
     * App detector execution state.
     */
    val appDetectorExecuted: Boolean = false,

    /**
     * App detector completion state.
     */
    val appDetectorCompleted: Boolean = false,

    /**
     * Code detector execution state.
     */
    val codeDetectorExecuted: Boolean = false,

    /**
     * Code detector completion state.
     */
    val codeDetectorCompleted: Boolean = false,

    /**
     * Resource detector execution state.
     */
    val resourceDetectorExecuted: Boolean = false,

    /**
     * Resource detector completion state.
     */
    val resourceDetectorCompleted: Boolean = false,

    /**
     * Signature detector execution state.
     */
    val signatureDetectorExecuted: Boolean = false,

    /**
     * Signature detector completion state.
     */
    val signatureDetectorCompleted: Boolean = false,

    /**
     * Package detector execution state.
     */
    val packageDetectorExecuted: Boolean = false,

    /**
     * Package detector completion state.
     */
    val packageDetectorCompleted: Boolean = false,

    /**
     * Runtime detector execution state.
     */
    val runtimeDetectorExecuted: Boolean = false,

    /**
     * Runtime detector completion state.
     */
    val runtimeDetectorCompleted: Boolean = false
)
