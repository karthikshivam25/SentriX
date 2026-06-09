package com.sentrix.domain.services

import com.sentrix.domain.models.AppBehavior
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for behavioral analysis.
 *
 * This service monitors application behavior,
 * identifies suspicious patterns,
 * and generates behavior-related threat indicators.
 */
class BehavioralAnalysisService {

    /**
     * Analyzes application behaviors and generates threat indicators.
     *
     * Rules:
     * - Very high risk score -> CRITICAL threat.
     * - Excessive permission usage -> HIGH threat.
     * - Excessive network activity -> MEDIUM threat.
     * - Excessive background activity -> LOW threat.
     */
    suspend fun analyzeBehaviors(
        behaviors: List<AppBehavior>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        behaviors.mapNotNull { behavior ->

            when {

                // Extremely risky behavior detected
                behavior.riskScore >= 90 -> {
                    ThreatIndicator(
                        id = behavior.appId,
                        threatName = "Malicious Application Behavior",
                        severity = "CRITICAL",
                        description = "Application exhibits highly suspicious behavior",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Excessive permission usage
                behavior.suspiciousPermissions >= 10 -> {
                    ThreatIndicator(
                        id = behavior.appId,
                        threatName = "Permission Abuse Detected",
                        severity = "HIGH",
                        description = "Application is requesting excessive sensitive permissions",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Unusual network activity
                behavior.networkRequests >= 1000 -> {
                    ThreatIndicator(
                        id = behavior.appId,
                        threatName = "Suspicious Network Activity",
                        severity = "MEDIUM",
                        description = "Application is generating unusual network traffic",
                        timestamp = System.currentTimeMillis()
                    )
                }

                // Excessive background activity
                behavior.backgroundProcesses >= 20 -> {
                    ThreatIndicator(
                        id = behavior.appId,
                        threatName = "Abnormal Background Activity",
                        severity = "LOW",
                        description = "Application is running excessive background processes",
                        timestamp = System.currentTimeMillis()
                    )
                }

                else -> null
            }
        }
    }

    /**
     * Returns applications with high-risk behavior.
     */
    suspend fun getHighRiskApplications(
        behaviors: List<AppBehavior>
    ): List<AppBehavior> = withContext(Dispatchers.Default) {

        behaviors.filter {
            it.riskScore >= 90
        }
    }

    /**
     * Returns applications with suspicious permission usage.
     */
    suspend fun getPermissionAbuseApplications(
        behaviors: List<AppBehavior>
    ): List<AppBehavior> = withContext(Dispatchers.Default) {

        behaviors.filter {
            it.suspiciousPermissions >= 10
        }
    }

    /**
     * Returns applications with unusual network activity.
     */
    suspend fun getSuspiciousNetworkApplications(
        behaviors: List<AppBehavior>
    ): List<AppBehavior> = withContext(Dispatchers.Default) {

        behaviors.filter {
            it.networkRequests >= 1000
        }
    }

    /**
     * Returns applications with excessive background activity.
     */
    suspend fun getBackgroundProcessAbuseApplications(
        behaviors: List<AppBehavior>
    ): List<AppBehavior> = withContext(Dispatchers.Default) {

        behaviors.filter {
            it.backgroundProcesses >= 20
        }
    }

    /**
     * Calculates behavioral risk score.
     *
     * CRITICAL = 40
     * HIGH     = 30
     * MEDIUM   = 20
     * LOW      = 10
     *
     * Maximum score = 100.
     */
    suspend fun calculateBehavioralRiskScore(
        indicators: List<ThreatIndicator>
    ): Int = withContext(Dispatchers.Default) {

        indicators.sumOf {
            when (it.severity.uppercase()) {
                "CRITICAL" -> 40
                "HIGH" -> 30
                "MEDIUM" -> 20
                "LOW" -> 10
                else -> 0
            }
        }.coerceAtMost(100)
    }

    /**
     * Determines whether suspicious behaviors exist.
     */
    suspend fun hasSuspiciousBehavior(
        indicators: List<ThreatIndicator>
    ): Boolean = withContext(Dispatchers.Default) {

        indicators.isNotEmpty()
    }

    /**
     * Returns critical behavioral threats.
     */
    suspend fun getCriticalBehavioralThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("CRITICAL", ignoreCase = true)
        }
    }

    /**
     * Returns high-priority behavioral threats.
     */
    suspend fun getHighPriorityBehavioralThreats(
        indicators: List<ThreatIndicator>
    ): List<ThreatIndicator> = withContext(Dispatchers.Default) {

        indicators.filter {
            it.severity.equals("HIGH", ignoreCase = true)
        }
    }

    /**
     * Generates a behavioral analysis summary.
     */
    suspend fun generateBehaviorSummary(
        behaviors: List<AppBehavior>
    ): String = withContext(Dispatchers.Default) {

        val totalApps = behaviors.size

        val highRiskApps = behaviors.count {
            it.riskScore >= 90
        }

        val permissionAbuseApps = behaviors.count {
            it.suspiciousPermissions >= 10
        }

        val networkRiskApps = behaviors.count {
            it.networkRequests >= 1000
        }

        buildString {
            appendLine("Behavioral Analysis Summary")
            appendLine("---------------------------")
            appendLine("Total Applications: $totalApps")
            appendLine("High Risk Applications: $highRiskApps")
            appendLine("Permission Abuse Cases: $permissionAbuseApps")
            appendLine("Suspicious Network Activities: $networkRiskApps")
            appendLine(
                if (highRiskApps > 0)
                    "Status: Suspicious Behavior Detected"
                else
                    "Status: Normal Behavior"
            )
        }
    }

    /**
     * Determines whether application behavior appears safe.
     */
    suspend fun areBehaviorsSafe(
        behaviors: List<AppBehavior>
    ): Boolean = withContext(Dispatchers.Default) {

        behaviors.none {
            it.riskScore >= 90 ||
            it.suspiciousPermissions >= 10 ||
            it.networkRequests >= 1000
        }
    }
}
