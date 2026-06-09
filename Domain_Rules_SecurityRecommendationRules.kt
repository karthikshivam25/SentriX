package com.sentrix.domain.rules

/**
 * SentriX Security Recommendation Rules
 *
 * Centralized recommendation engine that generates
 * security guidance based on risk levels, threat types,
 * device integrity, network security, and protection status.
 */
object SecurityRecommendationRules {

    enum class RecommendationPriority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    data class SecurityRecommendation(
        val title: String,
        val description: String,
        val priority: RecommendationPriority,
        val actionRequired: Boolean
    )

    /**
     * Generate recommendations based on overall risk.
     */
    fun generateRiskRecommendations(
        riskScore: Int
    ): List<SecurityRecommendation> {

        val recommendations = mutableListOf<SecurityRecommendation>()

        when {
            riskScore >= 85 -> {
                recommendations.add(
                    SecurityRecommendation(
                        title = "Immediate Security Review",
                        description = "Critical security risks detected. Immediate investigation is required.",
                        priority = RecommendationPriority.CRITICAL,
                        actionRequired = true
                    )
                )
            }

            riskScore >= 65 -> {
                recommendations.add(
                    SecurityRecommendation(
                        title = "Investigate Active Threats",
                        description = "High-risk security indicators detected.",
                        priority = RecommendationPriority.HIGH,
                        actionRequired = true
                    )
                )
            }

            riskScore >= 40 -> {
                recommendations.add(
                    SecurityRecommendation(
                        title = "Review Security Status",
                        description = "Moderate security concerns detected.",
                        priority = RecommendationPriority.MEDIUM,
                        actionRequired = false
                    )
                )
            }
        }

        return recommendations
    }

    /**
     * Generate recommendations for rooted devices.
     */
    fun generateRootRecommendations(
        isRooted: Boolean
    ): List<SecurityRecommendation> {

        if (!isRooted) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title = "Restrict Sensitive Operations",
                description = "Rooted devices increase attack surface and reduce platform security guarantees.",
                priority = RecommendationPriority.HIGH,
                actionRequired = true
            ),
            SecurityRecommendation(
                title = "Verify Device Integrity",
                description = "Perform a full device integrity assessment.",
                priority = RecommendationPriority.HIGH,
                actionRequired = true
            )
        )
    }

    /**
     * Generate recommendations for network security.
     */
    fun generateNetworkRecommendations(
        networkRiskScore: Int,
        vpnEnabled: Boolean
    ): List<SecurityRecommendation> {

        val recommendations = mutableListOf<SecurityRecommendation>()

        if (networkRiskScore >= 60) {
            recommendations.add(
                SecurityRecommendation(
                    title = "Avoid Sensitive Transactions",
                    description = "Current network environment is considered high risk.",
                    priority = RecommendationPriority.HIGH,
                    actionRequired = true
                )
            )
        }

        if (!vpnEnabled) {
            recommendations.add(
                SecurityRecommendation(
                    title = "Enable VPN Protection",
                    description = "Use a trusted VPN when accessing public networks.",
                    priority = RecommendationPriority.MEDIUM,
                    actionRequired = false
                )
            )
        }

        return recommendations
    }

    /**
     * Generate recommendations for malware detections.
     */
    fun generateMalwareRecommendations(
        malwareDetected: Boolean
    ): List<SecurityRecommendation> {

        if (!malwareDetected) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title = "Run Deep Security Scan",
                description = "Malicious activity has been detected on the device.",
                priority = RecommendationPriority.CRITICAL,
                actionRequired = true
            ),
            SecurityRecommendation(
                title = "Quarantine Suspicious Components",
                description = "Isolate affected files and applications.",
                priority = RecommendationPriority.CRITICAL,
                actionRequired = true
            )
        )
    }

    /**
     * Generate recommendations for realtime protection.
     */
    fun generateProtectionRecommendations(
        protectionEnabled: Boolean
    ): List<SecurityRecommendation> {

        if (protectionEnabled) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title = "Enable Realtime Protection",
                description = "Realtime protection helps prevent threats before execution.",
                priority = RecommendationPriority.HIGH,
                actionRequired = true
            )
        )
    }

    /**
     * Generate recommendations for outdated systems.
     */
    fun generateUpdateRecommendations(
        systemOutdated: Boolean
    ): List<SecurityRecommendation> {

        if (!systemOutdated) {
            return emptyList()
        }

        return listOf(
            SecurityRecommendation(
                title = "Install Security Updates",
                description = "Device software is outdated and may contain known vulnerabilities.",
                priority = RecommendationPriority.HIGH,
                actionRequired = true
            )
        )
    }

    /**
     * Merge and sort recommendations by priority.
     */
    fun prioritizeRecommendations(
        recommendations: List<SecurityRecommendation>
    ): List<SecurityRecommendation> {

        return recommendations.sortedByDescending {
            when (it.priority) {
                RecommendationPriority.CRITICAL -> 4
                RecommendationPriority.HIGH -> 3
                RecommendationPriority.MEDIUM -> 2
                RecommendationPriority.LOW -> 1
            }
        }
    }

    /**
     * Determine whether urgent user attention is required.
     */
    fun requiresImmediateAttention(
        recommendations: List<SecurityRecommendation>
    ): Boolean {

        return recommendations.any {
            it.priority == RecommendationPriority.CRITICAL
        }
    }

    /**
     * Generate complete recommendation set.
     */
    fun generateRecommendations(
        riskScore: Int,
        isRooted: Boolean,
        malwareDetected: Boolean,
        networkRiskScore: Int,
        vpnEnabled: Boolean,
        protectionEnabled: Boolean,
        systemOutdated: Boolean
    ): List<SecurityRecommendation> {

        val recommendations = mutableListOf<SecurityRecommendation>()

        recommendations += generateRiskRecommendations(riskScore)
        recommendations += generateRootRecommendations(isRooted)
        recommendations += generateMalwareRecommendations(malwareDetected)
        recommendations += generateNetworkRecommendations(
            networkRiskScore,
            vpnEnabled
        )
        recommendations += generateProtectionRecommendations(
            protectionEnabled
        )
        recommendations += generateUpdateRecommendations(
            systemOutdated
        )

        return prioritizeRecommendations(recommendations)
    }
}
