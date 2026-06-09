package com.sentrix.domain.services

import com.sentrix.domain.models.PermissionAnalysis
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for analyzing application permissions.
 *
 * This service identifies risky permissions,
 * evaluates permission abuse patterns,
 * and generates permission-related threat indicators.
 */
class PermissionAnalysisService {

    /**
     * Analyzes permission data and generates threat indicators.
     *
     * Rules:
     * - Critical permissions → HIGH severity.
     * - Dangerous permissions → MEDIUM severity.
     * - Excessive permissions → LOW severity.
     */
    suspend fun analyzePermissions(
        permissions: List<PermissionAnalysis>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        permissions.mapNotNull { permission ->

            when {

                // Critical permission detected
                permission.isCritical -> {
                    ThreatIndicator(
                        id = permission.permissionId,
                        threatName = "Critical Permission Access",
                        severity = "HIGH",
                        description = "${permission.permissionName} has critical system access",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Dangerous permission detected
                permission.isDangerous -> {
                    ThreatIndicator(
                        id = permission.permissionId,
                        threatName = "Dangerous Permission",
                        severity = "MEDIUM",
                        description = "${permission.permissionName} may expose sensitive data",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Excessive permission requests
                permission.requestCount > 10 -> {
                    ThreatIndicator(
                        id = permission.permissionId,
                        threatName = "Permission Abuse",
                        severity = "LOW",
                        description = "Permission requested excessively",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns all critical permissions.
     */
    suspend fun getCriticalPermissions(
        permissions: List<PermissionAnalysis>
    ): List<PermissionAnalysis> = withContext(Dispatchers.Default) {

        permissions.filter {
            it.isCritical
        }
    }

    /**
     * Returns all dangerous permissions.
     */
    suspend fun getDangerousPermissions(
        permissions: List<PermissionAnalysis>
    ): List<PermissionAnalysis> = withContext(Dispatchers.Default) {

        permissions.filter {
            it.isDangerous
        }
    }

    /**
     * Calculates overall permission risk score.
     *
     * HIGH   = 30
     * MEDIUM = 20
     * LOW    = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculatePermissionRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Determines whether any permission threats exist.
     */
    suspend fun hasPermissionThreats(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns only high-priority permission threats.
     */
    suspend fun getHighPriorityPermissionThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Calculates the percentage of critical permissions.
     */
    suspend fun calculateCriticalPermissionPercentage(
        permissions: List<PermissionAnalysis>
    ): Double = withContext(Dispatchers.Default) {

        if (permissions.isEmpty()) return@withContext 0.0

        val criticalCount = permissions.count {
            it.isCritical
        }

        (criticalCount.toDouble() / permissions.size) * 100
    }

    /**
     * Generates a permission security summary.
     */
    suspend fun generatePermissionSummary(
        permissions: List<PermissionAnalysis>
    ): String = withContext(Dispatchers.Default) {

        val totalPermissions = permissions.size

        val criticalPermissions = permissions.count {
            it.isCritical
        }

        val dangerousPermissions = permissions.count {
            it.isDangerous
        }

        buildString {
            appendLine("Permission Security Summary")
            appendLine("---------------------------")
            appendLine("Total Permissions: $totalPermissions")
            appendLine("Critical Permissions: $criticalPermissions")
            appendLine("Dangerous Permissions: $dangerousPermissions")
            appendLine(
                if (criticalPermissions > 0)
                    "Status: Review Required"
                else
                    "Status: Safe"
            )
        }
    }

    /**
     * Checks whether permissions appear safe.
     */
    suspend fun arePermissionsSafe(
        permissions: List<PermissionAnalysis>
    ): Boolean = withContext(Dispatchers.Default) {

        permissions.none {
            it.isCritical || it.isDangerous
        }
    }
}
