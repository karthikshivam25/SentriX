package com.sentrix.domain.services

import com.sentrix.domain.models.SecurityMetrics
import com.sentrix.domain.models.ThreatIndicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Service responsible for generating security recommendations.
 *
 * This service analyzes threats and security metrics
 * and provides actionable recommendations to improve
 * overall system security.
 */
class SecurityRecommendationService {

    /**
     * Generates recommendations based on
     * detected threat indicators.
     */
    suspend fun generateThreatRecommendations(
        indicators: List<ThreatIndicator>
    ): List<String> = withContext(Dispatchers.Default) {

        val recommendations = mutableListOf<String>()

        if (indicators.any {
                it.severity.equals("CRITICAL", true)
            }) {

            recommendations.add(
                "Immediately investigate and resolve critical threats."
            )

            recommendations.add(
                "Perform a full system security scan."
            )
        }

        if (indicators.any {
                it.severity.equals("HIGH", true)
            }) {

            recommendations.add(
                "Review high-risk applications and permissions."
            )
        }

        if (indicators.any {
                it.threatName.contains("Malware", true)
            }) {

            recommendations.add(
                "Run a deep malware scan and quarantine infected files."
            )
        }

        if (recommendations.isEmpty()) {

            recommendations.add(
                "No immediate threats detected. Continue regular monitoring."
            )
        }

        recommendations
    }

    /**
     * Generates recommendations based on
     * current security metrics.
     */
    suspend fun generateMetricRecommendations(
        metrics: SecurityMetrics
    ): List<String> = withContext(Dispatchers.Default) {

        val recommendations = mutableListOf<String>()

        when {
            metrics.riskScore >= 80 -> {
                recommendations.add(
                    "Critical security posture detected. Immediate remediation required."
                )
            }

            metrics.riskScore >= 60 -> {
                recommendations.add(
                    "Review active threats and strengthen protection settings."
                )
            }

            metrics.riskScore >= 40 -> {
                recommendations.add(
                    "Perform preventive maintenance and security reviews."
                )
            }

            else -> {
                recommendations.add(
                    "Security posture is healthy. Continue routine monitoring."
                )
            }
        }

        if (metrics.compromisedDevices > 0) {
            recommendations.add(
                "Investigate compromised devices and verify device integrity."
            )
        }

        if (metrics.threatsDetected > 0) {
            recommendations.add(
                "Schedule regular scans to monitor threat activity."
            )
        }

        recommendations
    }

    /**
     * Generates recommendations based on
     * overall risk score.
     */
    suspend fun generateRiskRecommendations(
        riskScore: Int
    ): List<String> = withContext(Dispatchers.Default) {

        when {
            riskScore >= 80 -> listOf(
                "Enable all security modules immediately.",
                "Perform deep scans across the system.",
                "Review all active security alerts."
            )

            riskScore >= 60 -> listOf(
                "Increase scan frequency.",
                "Review suspicious activities and alerts."
            )

            riskScore >= 40 -> listOf(
                "Monitor threat trends closely.",
                "Keep protection features enabled."
            )

            else -> listOf(
                "Maintain current security practices.",
                "Perform regular system scans."
            )
        }
    }

    /**
     * Generates personalized recommendations
     * from threats and metrics.
     */
    suspend fun generateRecommendations(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): List<String> = withContext(Dispatchers.Default) {

        buildList {
            addAll(generateThreatRecommendations(indicators))
            addAll(generateMetricRecommendations(metrics))
        }.distinct()
    }

    /**
     * Returns recommendations for critical threats only.
     */
    suspend fun getCriticalThreatRecommendations(
        indicators: List<ThreatIndicator>
    ): List<String> = withContext(Dispatchers.Default) {

        if (indicators.none {
                it.severity.equals("CRITICAL", true)
            }) {
            return@withContext emptyList()
        }

        listOf(
            "Isolate affected devices immediately.",
            "Perform a complete forensic analysis.",
            "Review all recent security events.",
            "Update malware signatures and threat intelligence."
        )
    }

    /**
     * Generates a security improvement plan.
     */
    suspend fun generateImprovementPlan(
        metrics: SecurityMetrics
    ): List<String> = withContext(Dispatchers.Default) {

        val plan = mutableListOf<String>()

        plan.add("Review overall security posture.")
        plan.add("Update security definitions.")
        plan.add("Perform scheduled scans.")

        if (metrics.riskScore >= 60) {
            plan.add("Conduct deep security assessment.")
            plan.add("Strengthen endpoint protection.")
        }

        if (metrics.compromisedDevices > 0) {
            plan.add("Remediate compromised devices.")
        }

        plan
    }

    /**
     * Generates a recommendation summary report.
     */
    suspend fun generateRecommendationSummary(
        indicators: List<ThreatIndicator>,
        metrics: SecurityMetrics
    ): String = withContext(Dispatchers.Default) {

        val recommendations =
            generateRecommendations(indicators, metrics)

        buildString {
            appendLine("SentriX Security Recommendation Summary")
            appendLine("---------------------------------------")
            appendLine("Risk Score: ${metrics.riskScore}")
            appendLine("Detected Threats: ${indicators.size}")
            appendLine()
            appendLine("Recommendations:")

            recommendations.forEachIndexed { index, recommendation ->
                appendLine("${index + 1}. $recommendation")
            }
        }
    }

    /**
     * Determines whether security improvements
     * are currently required.
     */
    suspend fun needsSecurityImprovement(
        metrics: SecurityMetrics
    ): Boolean = withContext(Dispatchers.Default) {

        metrics.riskScore >= 40 ||
        metrics.compromisedDevices > 0 ||
        metrics.threatsDetected > 0
    }
}
