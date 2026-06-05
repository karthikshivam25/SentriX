package com.sentrix.domain.usecases

import com.sentrix.domain.models.AppInfo
import com.sentrix.domain.repositories.PermissionRepository

/**
 * AnalyzePermissionsUseCase
 *
 * Responsible for analyzing application
 * permissions and identifying potential
 * security, privacy, and compliance risks
 * within the SentriX platform.
 *
 * This use case evaluates requested and
 * granted permissions, detects excessive
 * privilege usage, identifies dangerous
 * permission combinations, and generates
 * actionable security recommendations.
 *
 * Used by:
 * - PermissionAnalyzer
 * - ApplicationScanner
 * - SecurityDashboard
 * - MalwareDetectionEngine
 * - ThreatAnalysisManager
 * - PrivacyProtectionService
 * - ComplianceMonitoringSystem
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze application permissions
 * - Identify dangerous permissions
 * - Detect over-privileged applications
 * - Calculate permission risk scores
 * - Generate security recommendations
 * - Support privacy risk assessment
 */
class AnalyzePermissionsUseCase(
    private val permissionRepository: PermissionRepository
) {

    /**
     * Executes permission analysis for
     * the specified application.
     *
     * @param appInfo Application to analyze
     *
     * @return PermissionAnalysisResult
     */
    suspend operator fun invoke(
        appInfo: AppInfo
    ): PermissionAnalysisResult {

        val dangerousPermissions =
            permissionRepository
                .getDangerousPermissions()

        val highRiskCombinations =
            permissionRepository
                .getHighRiskPermissionCombinations()

        val detectedDangerousPermissions =
            appInfo.permissions.filter {
                dangerousPermissions.contains(it)
            }

        val matchedRiskCombinations =
            highRiskCombinations.filter { combination ->
                combination.permissions.all {
                    appInfo.permissions.contains(it)
                }
            }

        val riskLevel =
            determineRiskLevel(
                dangerousPermissionCount =
                    detectedDangerousPermissions.size,
                riskCombinationCount =
                    matchedRiskCombinations.size
            )

        val riskScore =
            calculateRiskScore(
                dangerousPermissionCount =
                    detectedDangerousPermissions.size,
                riskCombinationCount =
                    matchedRiskCombinations.size
            )

        return PermissionAnalysisResult(
            analyzedAt = System.currentTimeMillis(),
            applicationId = appInfo.appId,
            packageName = appInfo.packageName,
            totalPermissions =
                appInfo.permissions.size,
            dangerousPermissions =
                detectedDangerousPermissions,
            highRiskCombinations =
                matchedRiskCombinations,
            riskLevel = riskLevel,
            riskScore = riskScore,
            recommendations =
                generateRecommendations(
                    riskLevel
                )
        )
    }

    /**
     * Determines permission risk level.
     */
    private fun determineRiskLevel(
        dangerousPermissionCount: Int,
        riskCombinationCount: Int
    ): PermissionRiskLevel {

        return when {

            riskCombinationCount >= 3 ->
                PermissionRiskLevel.CRITICAL

            dangerousPermissionCount >= 8 ->
                PermissionRiskLevel.HIGH

            dangerousPermissionCount >= 4 ->
                PermissionRiskLevel.MEDIUM

            else ->
                PermissionRiskLevel.LOW
        }
    }

    /**
     * Calculates permission risk score.
     *
     * Range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        dangerousPermissionCount: Int,
        riskCombinationCount: Int
    ): Int {

        val score =
            (dangerousPermissionCount * 8) +
            (riskCombinationCount * 20)

        return score.coerceIn(0, 100)
    }

    /**
     * Generates permission security
     * recommendations.
     */
    private fun generateRecommendations(
        riskLevel: PermissionRiskLevel
    ): List<String> {

        return when (riskLevel) {

            PermissionRiskLevel.CRITICAL -> listOf(
                "Review application immediately",
                "Restrict unnecessary permissions",
                "Monitor application behavior",
                "Consider application removal"
            )

            PermissionRiskLevel.HIGH -> listOf(
                "Review dangerous permissions",
                "Limit sensitive data access",
                "Perform security assessment"
            )

            PermissionRiskLevel.MEDIUM -> listOf(
                "Review granted permissions",
                "Apply least-privilege principle"
            )

            PermissionRiskLevel.LOW -> listOf(
                "No significant permission risks detected"
            )
        }
    }
}

/**
 * PermissionAnalysisResult
 *
 * Represents the outcome of
 * permission analysis.
 */
data class PermissionAnalysisResult(

    /**
     * Analysis timestamp.
     */
    val analyzedAt: Long,

    /**
     * Application identifier.
     */
    val applicationId: String,

    /**
     * Application package name.
     */
    val packageName: String,

    /**
     * Total permissions requested.
     */
    val totalPermissions: Int,

    /**
     * Dangerous permissions detected.
     */
    val dangerousPermissions: List<String>,

    /**
     * High-risk permission
     * combinations detected.
     */
    val highRiskCombinations:
        List<PermissionCombination>,

    /**
     * Calculated risk level.
     */
    val riskLevel: PermissionRiskLevel,

    /**
     * Calculated risk score.
     */
    val riskScore: Int,

    /**
     * Security recommendations.
     */
    val recommendations: List<String>
)

/**
 * PermissionCombination
 *
 * Represents a potentially dangerous
 * combination of permissions.
 */
data class PermissionCombination(

    /**
     * Combination identifier.
     */
    val combinationId: String,

    /**
     * Combination name.
     */
    val name: String,

    /**
     * Permissions involved.
     */
    val permissions: List<String>,

    /**
     * Risk description.
     */
    val description: String
)

/**
 * Permission risk indicators.
 */
enum class PermissionRiskLevel {

    /**
     * Low permission risk.
     */
    LOW,

    /**
     * Moderate permission risk.
     */
    MEDIUM,

    /**
     * High permission risk.
     */
    HIGH,

    /**
     * Critical permission risk.
     */
    CRITICAL
}
