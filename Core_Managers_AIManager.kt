package com.sentrix.core.managers

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

/**
 * AIManager
 *
 * Responsibilities:
 * - Security recommendation generation
 * - Threat intelligence correlation
 * - Device risk assessment
 * - Security score calculation
 * - AI insight generation
 * - Scan result interpretation
 *
 * NOTE:
 * This implementation provides an offline AI engine.
 * It can later be connected to OpenAI, Gemini,
 * Azure AI, AWS Bedrock, or a custom SentriX AI backend.
 */
class AIManager(
    private val context: Context,
    private val threatManager: ThreatManager? = null,
    private val deviceManager: DeviceManager? = null,
    private val networkManager: NetworkManager? = null,
    private val malwareManager: MalwareManager? = null
) {

    private val insights =
        CopyOnWriteArrayList<AIInsight>()

    /**
     * Generate security insights.
     */
    suspend fun generateInsights(): List<AIInsight> =
        withContext(Dispatchers.Default) {

            insights.clear()

            analyzeThreats()
            analyzeDeviceHealth()
            analyzeNetworkSecurity()

            insights.toList()
        }

    /**
     * Calculate overall security score.
     */
    fun calculateSecurityScore(): Int {

        var score = 100

        threatManager?.let {

            score -= it.calculateThreatScore()
                .coerceAtMost(50)
        }

        networkManager?.let {

            score -= (
                100 -
                        it.calculateNetworkSecurityScore()
                ) / 2
        }

        deviceManager?.let {

            when (it.getDeviceHealth()) {

                DeviceManager.DeviceHealth.GOOD -> {}
                DeviceManager.DeviceHealth.FAIR -> score -= 10
                DeviceManager.DeviceHealth.POOR -> score -= 20
                DeviceManager.DeviceHealth.CRITICAL -> score -= 35
            }
        }

        return score.coerceIn(0, 100)
    }

    /**
     * Determine security level.
     */
    fun getSecurityLevel(): SecurityLevel {

        return when (calculateSecurityScore()) {

            in 90..100 -> SecurityLevel.EXCELLENT
            in 75..89 -> SecurityLevel.GOOD
            in 50..74 -> SecurityLevel.MODERATE
            in 25..49 -> SecurityLevel.POOR
            else -> SecurityLevel.CRITICAL
        }
    }

    /**
     * Analyze threats.
     */
    private fun analyzeThreats() {

        val threats =
            threatManager?.getThreats()
                ?: emptyList()

        if (threats.isEmpty()) {

            insights.add(
                AIInsight(
                    id = UUID.randomUUID().toString(),
                    title = "No Active Threats",
                    description =
                    "No security threats were detected.",
                    priority = InsightPriority.LOW
                )
            )

            return
        }

        if (threats.size >= 5) {

            insights.add(
                AIInsight(
                    id = UUID.randomUUID().toString(),
                    title = "Multiple Threats Detected",
                    description =
                    "Several security threats require attention.",
                    priority = InsightPriority.CRITICAL
                )
            )
        }
    }

    /**
     * Analyze device health.
     */
    private fun analyzeDeviceHealth() {

        val health =
            deviceManager?.getDeviceHealth()
                ?: return

        when (health) {

            DeviceManager.DeviceHealth.CRITICAL -> {

                insights.add(
                    AIInsight(
                        id = UUID.randomUUID().toString(),
                        title = "Critical Device Health",
                        description =
                        "Device resources are critically low.",
                        priority = InsightPriority.CRITICAL
                    )
                )
            }

            DeviceManager.DeviceHealth.POOR -> {

                insights.add(
                    AIInsight(
                        id = UUID.randomUUID().toString(),
                        title = "Poor Device Performance",
                        description =
                        "Storage or memory usage is very high.",
                        priority = InsightPriority.HIGH
                    )
                )
            }

            else -> Unit
        }
    }

    /**
     * Analyze network security.
     */
    private fun analyzeNetworkSecurity() {

        val score =
            networkManager?.calculateNetworkSecurityScore()
                ?: return

        if (score < 50) {

            insights.add(
                AIInsight(
                    id = UUID.randomUUID().toString(),
                    title = "Unsafe Network Detected",
                    description =
                    "Current network may expose your device to risks.",
                    priority = InsightPriority.HIGH
                )
            )
        }
    }

    /**
     * Generate recommendations.
     */
    fun generateRecommendations(): List<String> {

        val recommendations =
            mutableListOf<String>()

        if (calculateSecurityScore() < 80) {
            recommendations.add(
                "Run a full security scan."
            )
        }

        if (
            networkManager?.isVpnActive() == false
        ) {
            recommendations.add(
                "Enable a trusted VPN."
            )
        }

        if (
            deviceManager?.getStorageUsagePercent()
                ?.let { it > 85 } == true
        ) {
            recommendations.add(
                "Free storage space to improve security and performance."
            )
        }

        if (recommendations.isEmpty()) {

            recommendations.add(
                "Your device security posture looks healthy."
            )
        }

        return recommendations
    }

    /**
     * Generate AI report.
     */
    fun generateAIReport(): String {

        return buildString {

            appendLine("AI Security Report")
            appendLine("-------------------------")
            appendLine(
                "Security Score : ${
                    calculateSecurityScore()
                }"
            )

            appendLine(
                "Security Level : ${
                    getSecurityLevel()
                }"
            )

            appendLine()
            appendLine("Recommendations:")

            generateRecommendations()
                .forEach {
                    appendLine("• $it")
                }
        }
    }

    /**
     * AI insight model.
     */
    data class AIInsight(
        val id: String,
        val title: String,
        val description: String,
        val priority: InsightPriority
    )

    /**
     * Insight priority.
     */
    enum class InsightPriority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Security level.
     */
    enum class SecurityLevel {
        EXCELLENT,
        GOOD,
        MODERATE,
        POOR,
        CRITICAL
    }
}
