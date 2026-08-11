package com.sentrix.security.permissions

import android.Manifest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PermissionRiskAnalyzer
 *
 * Enterprise-grade risk analysis engine for Android application
 * permissions.
 *
 * Responsibilities:
 * - Calculate normalized permission risk scores.
 * - Evaluate dangerous permissions.
 * - Evaluate sensitive permissions.
 * - Detect high-risk permission combinations.
 * - Evaluate excessive permission usage.
 * - Consider granted versus declared permissions.
 * - Calculate risk confidence.
 * - Generate risk explanations.
 * - Generate security recommendations.
 *
 * This class does NOT:
 * - Request permissions.
 * - Modify permissions.
 * - Block applications.
 * - Perform malware analysis.
 *
 * It should be used after PermissionChecker and/or
 * PermissionAnalyzer have collected permission information.
 *
 * Architecture:
 *
 * PermissionChecker
 *       ↓
 * PermissionAnalyzer
 *       ↓
 * PermissionRiskAnalyzer
 *       ↓
 * PermissionRiskAssessment
 *       ↓
 * Threat / Security Report
 */
class PermissionRiskAnalyzer {

    /**
     * Performs a complete risk analysis from an existing
     * PermissionAnalysisReport.
     *
     * This is the preferred entry point when PermissionAnalyzer
     * has already analyzed the application.
     */
    suspend fun analyze(
        report: PermissionAnalysisReport
    ): PermissionRiskAssessment =
        withContext(Dispatchers.Default) {

            val factors =
                mutableListOf<PermissionRiskFactor>()

            evaluatePermissionVolume(
                report = report,
                factors = factors
            )

            evaluateDangerousPermissions(
                report = report,
                factors = factors
            )

            evaluateSensitivePermissions(
                report = report,
                factors = factors
            )

            evaluateCommunicationAccess(
                report = report,
                factors = factors
            )

            evaluateSensorAccess(
                report = report,
                factors = factors
            )

            evaluateLocationAccess(
                report = report,
                factors = factors
            )

            evaluatePersonalDataAccess(
                report = report,
                factors = factors
            )

            evaluateSuspiciousCombinations(
                report = report,
                factors = factors
            )

            evaluateHighSeverityFindings(
                report = report,
                factors = factors
            )

            val rawScore =
                calculateScore(
                    report = report,
                    factors = factors
                )

            val normalizedScore =
                rawScore.coerceIn(
                    MIN_RISK_SCORE,
                    MAX_RISK_SCORE
                )

            val riskLevel =
                determineRiskLevel(
                    normalizedScore
                )

            val confidence =
                calculateConfidence(
                    report = report,
                    factors = factors
                )

            val recommendations =
                generateRecommendations(
                    report = report,
                    factors = factors,
                    riskLevel = riskLevel
                )

            val explanation =
                generateExplanation(
                    report = report,
                    factors = factors,
                    riskLevel = riskLevel
                )

            PermissionRiskAssessment(
                packageName = report.packageName,
                applicationName = report.applicationName,
                riskScore = normalizedScore,
                riskLevel = riskLevel,
                confidence = confidence,
                factors = factors.sortedByDescending {
                    it.impact
                },
                recommendations = recommendations,
                explanation = explanation
            )
        }

    /**
     * Performs risk analysis directly from permission check
     * results.
     *
     * Useful when PermissionAnalyzer has not been invoked.
     */
    suspend fun analyzePermissionResults(
        packageName: String,
        applicationName: String?,
        results: List<PermissionCheckResult>
    ): PermissionRiskAssessment =
        withContext(Dispatchers.Default) {

            val findings =
                buildFindingsFromResults(results)

            val report =
                PermissionAnalysisReport(
                    packageName = packageName,
                    applicationName = applicationName,
                    status = PermissionAnalysisStatus.COMPLETED,
                    riskLevel = PermissionRiskLevel.LOW,
                    riskScore = 0,
                    totalPermissions = results.size,
                    grantedPermissions =
                        results.count { it.granted },
                    deniedPermissions =
                        results.count {
                            it.declared && !it.granted
                        },
                    dangerousPermissions =
                        results.count {
                            it.dangerous
                        },
                    grantedDangerousPermissions =
                        results.count {
                            it.dangerous && it.granted
                        },
                    sensitivePermissions =
                        results.count {
                            it.sensitive
                        },
                    findings = findings
                )

            analyze(report)
        }

    /**
     * Evaluates the total permission footprint.
     */
    private fun evaluatePermissionVolume(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        when {

            report.totalPermissions >= 30 -> {

                factors += PermissionRiskFactor(
                    id = "PERMISSION_VOLUME_CRITICAL",
                    title = "Very Large Permission Footprint",
                    description =
                        "The application requests " +
                        "${report.totalPermissions} permissions.",
                    category =
                        PermissionRiskFactorCategory.PERMISSION_VOLUME,
                    impact = 20,
                    confidence = 0.90f
                )
            }

            report.totalPermissions >= 20 -> {

                factors += PermissionRiskFactor(
                    id = "PERMISSION_VOLUME_HIGH",
                    title = "Large Permission Footprint",
                    description =
                        "The application requests " +
                        "${report.totalPermissions} permissions.",
                    category =
                        PermissionRiskFactorCategory.PERMISSION_VOLUME,
                    impact = 14,
                    confidence = 0.88f
                )
            }

            report.totalPermissions >= 15 -> {

                factors += PermissionRiskFactor(
                    id = "PERMISSION_VOLUME_MEDIUM",
                    title = "Elevated Permission Footprint",
                    description =
                        "The application requests " +
                        "${report.totalPermissions} permissions.",
                    category =
                        PermissionRiskFactorCategory.PERMISSION_VOLUME,
                    impact = 8,
                    confidence = 0.85f
                )
            }
        }
    }

    /**
     * Evaluates dangerous permissions that are actually granted.
     */
    private fun evaluateDangerousPermissions(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val count =
            report.grantedDangerousPermissions

        when {

            count >= 15 -> {

                factors += PermissionRiskFactor(
                    id = "DANGEROUS_PERMISSION_CRITICAL",
                    title = "Extensive Dangerous Permissions",
                    description =
                        "$count dangerous permissions are currently " +
                        "granted to the application.",
                    category =
                        PermissionRiskFactorCategory.DANGEROUS_PERMISSION,
                    impact = 25,
                    confidence = 0.95f
                )
            }

            count >= 10 -> {

                factors += PermissionRiskFactor(
                    id = "DANGEROUS_PERMISSION_HIGH",
                    title = "Many Dangerous Permissions",
                    description =
                        "$count dangerous permissions are currently " +
                        "granted to the application.",
                    category =
                        PermissionRiskFactorCategory.DANGEROUS_PERMISSION,
                    impact = 18,
                    confidence = 0.95f
                )
            }

            count >= 6 -> {

                factors += PermissionRiskFactor(
                    id = "DANGEROUS_PERMISSION_MEDIUM",
                    title = "Multiple Dangerous Permissions",
                    description =
                        "$count dangerous permissions are currently " +
                        "granted to the application.",
                    category =
                        PermissionRiskFactorCategory.DANGEROUS_PERMISSION,
                    impact = 10,
                    confidence = 0.94f
                )
            }

            count >= 3 -> {

                factors += PermissionRiskFactor(
                    id = "DANGEROUS_PERMISSION_LOW",
                    title = "Dangerous Permissions Granted",
                    description =
                        "$count dangerous permissions are currently " +
                        "granted to the application.",
                    category =
                        PermissionRiskFactorCategory.DANGEROUS_PERMISSION,
                    impact = 5,
                    confidence = 0.92f
                )
            }
        }
    }

    /**
     * Evaluates sensitive permissions.
     */
    private fun evaluateSensitivePermissions(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val grantedSensitive =
            report.findings
                .flatMap { it.permissions }
                .distinct()

        val sensitiveFinding =
            report.findings.any {
                it.category ==
                        PermissionFindingCategory.SENSITIVE_ACCESS
            }

        if (!sensitiveFinding &&
            report.sensitivePermissions == 0
        ) {
            return
        }

        val impact =
            when {

                grantedSensitive.size >= 8 ->
                    20

                grantedSensitive.size >= 5 ->
                    15

                grantedSensitive.size >= 3 ->
                    10

                else ->
                    5
            }

        factors += PermissionRiskFactor(
            id = "SENSITIVE_PERMISSION_ACCESS",
            title = "Sensitive Permission Access",
            description =
                "The application's permission footprint includes " +
                "permissions capable of accessing sensitive device " +
                "or user information.",
            category =
                PermissionRiskFactorCategory.SENSITIVE_PERMISSION,
            impact = impact,
            confidence = 0.90f
        )
    }

    /**
     * Evaluates communication-related permissions.
     */
    private fun evaluateCommunicationAccess(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val finding =
            report.findings.firstOrNull {
                it.category ==
                        PermissionFindingCategory.COMMUNICATION_ACCESS
            }
                ?: return

        val hasSms =
            finding.permissions.any {
                it == Manifest.permission.READ_SMS ||
                        it == Manifest.permission.RECEIVE_SMS ||
                        it == Manifest.permission.SEND_SMS
            }

        val hasCallAccess =
            finding.permissions.any {
                it == Manifest.permission.READ_CALL_LOG ||
                        it == Manifest.permission.WRITE_CALL_LOG ||
                        it == Manifest.permission.CALL_PHONE
            }

        val impact =
            when {

                hasSms && hasCallAccess ->
                    18

                hasSms ->
                    15

                hasCallAccess ->
                    10

                else ->
                    5
            }

        factors += PermissionRiskFactor(
            id = "COMMUNICATION_PERMISSION_ACCESS",
            title = "Communication Data Access",
            description =
                "The application has access to communication-related " +
                "permissions such as SMS or call functionality.",
            category =
                PermissionRiskFactorCategory.COMMUNICATION_ACCESS,
            impact = impact,
            confidence = 0.94f
        )
    }

    /**
     * Evaluates camera and microphone access.
     */
    private fun evaluateSensorAccess(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val finding =
            report.findings.firstOrNull {
                it.category ==
                        PermissionFindingCategory.SENSOR_ACCESS
            }
                ?: return

        val hasCamera =
            finding.permissions.contains(
                Manifest.permission.CAMERA
            )

        val hasMicrophone =
            finding.permissions.contains(
                Manifest.permission.RECORD_AUDIO
            )

        val impact =
            if (hasCamera && hasMicrophone) {
                12
            } else {
                7
            }

        factors += PermissionRiskFactor(
            id = "SENSOR_PERMISSION_ACCESS",
            title = "Sensor Access",
            description =
                "The application has access to camera and/or " +
                "microphone functionality.",
            category =
                PermissionRiskFactorCategory.SENSOR_ACCESS,
            impact = impact,
            confidence = 0.92f
        )
    }

    /**
     * Evaluates location permissions.
     */
    private fun evaluateLocationAccess(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val finding =
            report.findings.firstOrNull {
                it.category ==
                        PermissionFindingCategory.LOCATION_ACCESS
            }
                ?: return

        val precise =
            finding.permissions.contains(
                Manifest.permission.ACCESS_FINE_LOCATION
            )

        factors += PermissionRiskFactor(
            id = "LOCATION_PERMISSION_ACCESS",
            title = "Location Access",
            description =
                if (precise) {
                    "The application has access to precise " +
                    "device location."
                } else {
                    "The application has access to approximate " +
                    "device location."
                },
            category =
                PermissionRiskFactorCategory.LOCATION_ACCESS,
            impact =
                if (precise) 8 else 5,
            confidence = 0.94f
        )
    }

    /**
     * Evaluates access to personal data such as contacts.
     */
    private fun evaluatePersonalDataAccess(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val personalDataFindings =
            report.findings.filter {
                it.category ==
                        PermissionFindingCategory.PERSONAL_DATA
            }

        if (personalDataFindings.isEmpty()) {
            return
        }

        val permissionCount =
            personalDataFindings
                .flatMap { it.permissions }
                .distinct()
                .size

        factors += PermissionRiskFactor(
            id = "PERSONAL_DATA_ACCESS",
            title = "Personal Data Access",
            description =
                "The application can access personal data " +
                "stored on the device.",
            category =
                PermissionRiskFactorCategory.PERSONAL_DATA,
            impact =
                when {
                    permissionCount >= 3 -> 10
                    permissionCount >= 2 -> 7
                    else -> 5
                },
            confidence = 0.91f
        )
    }

    /**
     * Evaluates suspicious permission combinations detected
     * by PermissionAnalyzer.
     */
    private fun evaluateSuspiciousCombinations(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        val combinations =
            report.findings.filter {
                it.category ==
                        PermissionFindingCategory.SUSPICIOUS_COMBINATION
            }

        combinations.forEach { finding ->

            factors += PermissionRiskFactor(
                id = "COMBINATION_${finding.id}",
                title = finding.title,
                description = finding.description,
                category =
                    PermissionRiskFactorCategory.PERMISSION_COMBINATION,
                impact =
                    when (finding.severity) {

                        PermissionFindingSeverity.LOW ->
                            3

                        PermissionFindingSeverity.MEDIUM ->
                            7

                        PermissionFindingSeverity.HIGH ->
                            13

                        PermissionFindingSeverity.CRITICAL ->
                            20
                    },
                confidence = 0.80f
            )
        }
    }

    /**
     * Evaluates findings that have already been classified
     * as high or critical.
     */
    private fun evaluateHighSeverityFindings(
        report: PermissionAnalysisReport,
        factors: MutableList<PermissionRiskFactor>
    ) {

        report.findings
            .filter {
                it.severity ==
                        PermissionFindingSeverity.HIGH ||
                        it.severity ==
                        PermissionFindingSeverity.CRITICAL
            }
            .forEach { finding ->

                factors += PermissionRiskFactor(
                    id = "FINDING_${finding.id}",
                    title =
                        "High-Severity Finding: ${finding.title}",
                    description =
                        finding.description,
                    category =
                        PermissionRiskFactorCategory.SECURITY_FINDING,
                    impact =
                        when (finding.severity) {

                            PermissionFindingSeverity.HIGH ->
                                8

                            PermissionFindingSeverity.CRITICAL ->
                                15

                            else ->
                                0
                        },
                    confidence = 0.85f
                )
            }
    }

    /**
     * Calculates the final risk score.
     *
     * The score is normalized to 0..100.
     */
    private fun calculateScore(
        report: PermissionAnalysisReport,
        factors: List<PermissionRiskFactor>
    ): Int {

        var score =
            factors.sumOf {
                it.impact
            }

        /*
         * Granted permissions carry more risk than merely
         * declared permissions.
         */
        val grantedRatio =
            if (report.totalPermissions > 0) {
                report.grantedPermissions.toDouble() /
                        report.totalPermissions.toDouble()
            } else {
                0.0
            }

        if (grantedRatio >= 0.80) {
            score += 5
        }

        /*
         * Multiple independent high-risk signals should
         * increase the final score.
         */
        val highImpactFactors =
            factors.count {
                it.impact >= 12
            }

        if (highImpactFactors >= 3) {
            score += 10
        }

        if (highImpactFactors >= 5) {
            score += 10
        }

        /*
         * Correlation bonus for sensitive + dangerous access.
         */
        if (
            report.grantedDangerousPermissions >= 5 &&
            report.sensitivePermissions >= 3
        ) {
            score += 8
        }

        return score.coerceIn(
            MIN_RISK_SCORE,
            MAX_RISK_SCORE
        )
    }

    /**
     * Converts score into a risk classification.
     */
    private fun determineRiskLevel(
        score: Int
    ): PermissionRiskLevel {

        return when {

            score >= 80 ->
                PermissionRiskLevel.CRITICAL

            score >= 55 ->
                PermissionRiskLevel.HIGH

            score >= 25 ->
                PermissionRiskLevel.MEDIUM

            else ->
                PermissionRiskLevel.LOW
        }
    }

    /**
     * Calculates confidence based on the quantity and
     * quality of available evidence.
     */
    private fun calculateConfidence(
        report: PermissionAnalysisReport,
        factors: List<PermissionRiskFactor>
    ): Float {

        if (report.totalPermissions == 0) {
            return 0.20f
        }

        if (factors.isEmpty()) {
            return 0.70f
        }

        val averageConfidence =
            factors
                .map { it.confidence }
                .average()
                .toFloat()

        /*
         * More independent signals provide better confidence.
         */
        val evidenceBonus =
            when {

                factors.size >= 6 -> 0.10f

                factors.size >= 3 -> 0.05f

                else -> 0.0f
            }

        return (
            averageConfidence + evidenceBonus
        ).coerceIn(
            0.0f,
            1.0f
        )
    }

    /**
     * Generates actionable recommendations.
     */
    private fun generateRecommendations(
        report: PermissionAnalysisReport,
        factors: List<PermissionRiskFactor>,
        riskLevel: PermissionRiskLevel
    ): List<PermissionRecommendation> {

        val recommendations =
            mutableListOf<PermissionRecommendation>()

        if (
            report.grantedDangerousPermissions > 0
        ) {

            recommendations += PermissionRecommendation(
                id = "REVIEW_DANGEROUS_PERMISSIONS",
                title = "Review Dangerous Permissions",
                description =
                    "Verify that every granted dangerous " +
                    "permission is required by the application's " +
                    "legitimate functionality.",
                priority =
                    PermissionRecommendationPriority.HIGH
            )
        }

        if (
            report.sensitivePermissions > 0
        ) {

            recommendations += PermissionRecommendation(
                id = "REVIEW_SENSITIVE_ACCESS",
                title = "Review Sensitive Data Access",
                description =
                    "Review access to sensitive device and " +
                    "personal information and confirm that the " +
                    "permissions are functionally justified.",
                priority =
                    PermissionRecommendationPriority.HIGH
            )
        }

        if (
            factors.any {
                it.category ==
                        PermissionRiskFactorCategory.PERMISSION_VOLUME
            }
        ) {

            recommendations += PermissionRecommendation(
                id = "REDUCE_PERMISSION_SURFACE",
                title = "Reduce Permission Surface",
                description =
                    "Remove unnecessary permission declarations " +
                    "to reduce application attack surface and " +
                    "privacy exposure.",
                priority =
                    PermissionRecommendationPriority.MEDIUM
            )
        }

        if (
            factors.any {
                it.category ==
                        PermissionRiskFactorCategory.COMMUNICATION_ACCESS
            }
        ) {

            recommendations += PermissionRecommendation(
                id = "REVIEW_COMMUNICATION_ACCESS",
                title = "Review Communication Access",
                description =
                    "Verify that SMS and call-related access is " +
                    "necessary and consistent with the application's " +
                    "expected functionality.",
                priority =
                    PermissionRecommendationPriority.HIGH
            )
        }

        if (
            factors.any {
                it.category ==
                        PermissionRiskFactorCategory.PERMISSION_COMBINATION
            }
        ) {

            recommendations += PermissionRecommendation(
                id = "PERFORM_BEHAVIORAL_ANALYSIS",
                title = "Perform Behavioral Analysis",
                description =
                    "Correlate the permission combination with " +
                    "application behavior, network activity and " +
                    "other SentriX security signals.",
                priority =
                    PermissionRecommendationPriority.HIGH
            )
        }

        when (riskLevel) {

            PermissionRiskLevel.CRITICAL -> {

                recommendations += PermissionRecommendation(
                    id = "ESCALATE_CRITICAL_PERMISSION_RISK",
                    title = "Escalate for Security Investigation",
                    description =
                        "The permission footprint contains multiple " +
                        "high-impact indicators and should receive " +
                        "additional security investigation.",
                    priority =
                        PermissionRecommendationPriority.CRITICAL
                )
            }

            PermissionRiskLevel.HIGH -> {

                recommendations += PermissionRecommendation(
                    id = "ESCALATE_HIGH_PERMISSION_RISK",
                    title = "Perform Additional Security Review",
                    description =
                        "Correlate permission findings with malware, " +
                        "behavioral and threat-intelligence analysis.",
                    priority =
                        PermissionRecommendationPriority.HIGH
                )
            }

            else -> Unit
        }

        return recommendations
            .distinctBy {
                it.id
            }
    }

    /**
     * Generates a human-readable risk explanation.
     */
    private fun generateExplanation(
        report: PermissionAnalysisReport,
        factors: List<PermissionRiskFactor>,
        riskLevel: PermissionRiskLevel
    ): String {

        if (report.totalPermissions == 0) {
            return "No requested permissions were available for analysis."
        }

        val majorFactors =
            factors
                .filter {
                    it.impact >= 10
                }
                .take(3)

        if (majorFactors.isEmpty()) {

            return when (riskLevel) {

                PermissionRiskLevel.LOW ->
                    "The application's permission footprint does not " +
                    "currently contain significant high-impact indicators."

                PermissionRiskLevel.MEDIUM ->
                    "The application has some permission-related " +
                    "indicators that warrant review."

                PermissionRiskLevel.HIGH ->
                    "The application's permission footprint contains " +
                    "multiple indicators requiring additional review."

                PermissionRiskLevel.CRITICAL ->
                    "The application's permission footprint contains " +
                    "multiple high-impact indicators requiring " +
                    "immediate security investigation."
            }
        }

        val factorText =
            majorFactors.joinToString(
                separator = ", "
            ) {
                it.title
            }

        return "Permission risk is classified as $riskLevel " +
                "based primarily on: $factorText."
    }

    /**
     * Creates basic findings when only PermissionCheckResult
     * objects are available.
     */
    private fun buildFindingsFromResults(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val findings =
            mutableListOf<PermissionFinding>()

        val grantedSensitive =
            results.filter {
                it.sensitive && it.granted
            }

        if (grantedSensitive.isNotEmpty()) {

            findings += PermissionFinding(
                id = "GRANTED_SENSITIVE_PERMISSIONS",
                title = "Sensitive Permissions Granted",
                description =
                    "The application has granted access to " +
                    "${grantedSensitive.size} sensitive permission(s).",
                severity =
                    if (grantedSensitive.size >= 5) {
                        PermissionFindingSeverity.HIGH
                    } else {
                        PermissionFindingSeverity.MEDIUM
                    },
                category =
                    PermissionFindingCategory.SENSITIVE_ACCESS,
                permissions =
                    grantedSensitive.map {
                        it.permission
                    }
            )
        }

        val grantedCommunication =
            results.filter {
                it.granted &&
                        (
                            it.permission ==
                                    Manifest.permission.READ_SMS ||
                            it.permission ==
                                    Manifest.permission.RECEIVE_SMS ||
                            it.permission ==
                                    Manifest.permission.SEND_SMS ||
                            it.permission ==
                                    Manifest.permission.READ_CALL_LOG ||
                            it.permission ==
                                    Manifest.permission.WRITE_CALL_LOG ||
                            it.permission ==
                                    Manifest.permission.CALL_PHONE
                        )
            }

        if (grantedCommunication.isNotEmpty()) {

            findings += PermissionFinding(
                id = "COMMUNICATION_ACCESS",
                title = "Communication Access Granted",
                description =
                    "The application has access to SMS or " +
                    "call-related functionality.",
                severity =
                    PermissionFindingSeverity.HIGH,
                category =
                    PermissionFindingCategory.COMMUNICATION_ACCESS,
                permissions =
                    grantedCommunication.map {
                        it.permission
                    }
            )
        }

        val grantedLocation =
            results.filter {
                it.granted &&
                        (
                            it.permission ==
                                    Manifest.permission.ACCESS_FINE_LOCATION ||
                            it.permission ==
                                    Manifest.permission.ACCESS_COARSE_LOCATION
                        )
            }

        if (grantedLocation.isNotEmpty()) {

            findings += PermissionFinding(
                id = "LOCATION_ACCESS",
                title = "Location Access Granted",
                description =
                    "The application has access to device location.",
                severity =
                    PermissionFindingSeverity.MEDIUM,
                category =
                    PermissionFindingCategory.LOCATION_ACCESS,
                permissions =
                    grantedLocation.map {
                        it.permission
                    }
            )
        }

        return findings
    }

    companion object {

        /**
         * Minimum supported risk score.
         */
        private const val MIN_RISK_SCORE = 0

        /**
         * Maximum normalized risk score.
         */
        private const val MAX_RISK_SCORE = 100
    }
}

/**
 * Complete permission risk assessment.
 */
data class PermissionRiskAssessment(

    val packageName: String,

    val applicationName: String?,

    val riskScore: Int,

    val riskLevel: PermissionRiskLevel,

    /**
     * Confidence represented as 0.0 - 1.0.
     */
    val confidence: Float,

    val factors: List<PermissionRiskFactor>,

    val recommendations: List<PermissionRecommendation>,

    val explanation: String
) {

    /**
     * Indicates whether the application requires
     * additional investigation.
     */
    val requiresInvestigation: Boolean
        get() =
            riskLevel == PermissionRiskLevel.HIGH ||
                    riskLevel == PermissionRiskLevel.CRITICAL

    /**
     * Indicates whether the result has meaningful
     * high-impact evidence.
     */
    val hasHighImpactFactors: Boolean
        get() =
            factors.any {
                it.impact >= 12
            }

    /**
     * Human-readable confidence percentage.
     */
    val confidencePercentage: Int
        get() =
            (confidence * 100)
                .toInt()
                .coerceIn(0, 100)
}

/**
 * Individual factor contributing to permission risk.
 */
data class PermissionRiskFactor(

    val id: String,

    val title: String,

    val description: String,

    val category: PermissionRiskFactorCategory,

    /**
     * Impact contribution before normalization.
     */
    val impact: Int,

    /**
     * Confidence represented as 0.0 - 1.0.
     */
    val confidence: Float
)

/**
 * Permission risk-factor categories.
 */
enum class PermissionRiskFactorCategory {

    PERMISSION_VOLUME,

    DANGEROUS_PERMISSION,

    SENSITIVE_PERMISSION,

    COMMUNICATION_ACCESS,

    SENSOR_ACCESS,

    LOCATION_ACCESS,

    PERSONAL_DATA,

    PERMISSION_COMBINATION,

    SECURITY_FINDING
}

/**
 * Security recommendation generated from the
 * permission-risk assessment.
 */
data class PermissionRecommendation(

    val id: String,

    val title: String,

    val description: String,

    val priority: PermissionRecommendationPriority
)

/**
 * Recommendation priority.
 */
enum class PermissionRecommendationPriority {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}
