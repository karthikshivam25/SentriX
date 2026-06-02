package com.sentrix.core.helpers

import com.sentrix.core.enums.SecurityStatus

object AIRecommendationHelper {

    /**
     * Generate security recommendation
     */
    fun generateSecurityRecommendation(
        riskScore: Int,
        securityStatus: SecurityStatus
    ): String {

        return when (securityStatus) {

            SecurityStatus.CRITICAL -> {
                "Critical threats detected. Immediate action is strongly recommended."
            }

            SecurityStatus.DANGEROUS -> {
                "Dangerous activity identified. Review suspicious apps and permissions."
            }

            SecurityStatus.WARNING -> {
                "Potential risks detected. Monitor your device carefully."
            }

            SecurityStatus.SAFE -> {
                "Your device is mostly secure. Continue regular monitoring."
            }

            SecurityStatus.SECURE -> {
                "Excellent security posture detected. Your device appears protected."
            }
        }
    }

    /**
     * Generate permission recommendation
     */
    fun generatePermissionRecommendation(
        dangerousPermissions: List<String>
    ): String {

        return when {

            dangerousPermissions.isEmpty() -> {
                "No dangerous permissions detected."
            }

            dangerousPermissions.size >= 5 -> {
                "Several high-risk permissions detected. Consider revoking unnecessary access."
            }

            dangerousPermissions.size >= 3 -> {
                "Some sensitive permissions are enabled. Review application access settings."
            }

            else -> {
                "Minor permission risks detected. Periodic review is recommended."
            }
        }
    }

    /**
     * Generate malware recommendation
     */
    fun generateMalwareRecommendation(
        detectedThreats: Int
    ): String {

        return when {

            detectedThreats >= 10 -> {
                "Multiple threats identified. Immediate cleanup and device scan recommended."
            }

            detectedThreats >= 5 -> {
                "Several suspicious items found. Run a deep security scan."
            }

            detectedThreats >= 1 -> {
                "Potential malware detected. Review and remove suspicious applications."
            }

            else -> {
                "No malware threats currently detected."
            }
        }
    }

    /**
     * Generate VPN recommendation
     */
    fun generateVpnRecommendation(
        vpnEnabled: Boolean
    ): String {

        return if (vpnEnabled) {

            "VPN protection is active. Your network traffic is encrypted."

        } else {

            "VPN protection is disabled. Public network usage may expose sensitive data."
        }
    }

    /**
     * Generate root detection recommendation
     */
    fun generateRootRecommendation(
        rooted: Boolean
    ): String {

        return if (rooted) {

            "Root access detected. Device security protections may be compromised."

        } else {

            "No root access detected. Device integrity appears secure."
        }
    }

    /**
     * Generate emulator recommendation
     */
    fun generateEmulatorRecommendation(
        emulatorDetected: Boolean
    ): String {

        return if (emulatorDetected) {

            "Emulator environment detected. Security behavior may differ from physical devices."

        } else {

            "Physical device environment confirmed."
        }
    }

    /**
     * Generate battery optimization recommendation
     */
    fun generatePerformanceRecommendation(
        batteryLevel: Int,
        memoryUsagePercentage: Int
    ): String {

        return when {

            batteryLevel < 15 -> {
                "Low battery level detected. Enable battery optimization for extended protection."
            }

            memoryUsagePercentage > 85 -> {
                "High memory usage detected. Close unnecessary background applications."
            }

            memoryUsagePercentage > 70 -> {
                "Moderate memory pressure detected. Monitor active applications."
            }

            else -> {
                "Device performance appears stable."
            }
        }
    }

    /**
     * Generate overall AI insights
     */
    fun generateOverallInsights(
        riskScore: Int,
        detectedThreats: Int,
        vpnEnabled: Boolean,
        rooted: Boolean
    ): List<String> {

        val insights = mutableListOf<String>()

        insights.add(
            generateSecurityRecommendation(
                riskScore = riskScore,
                securityStatus = getSecurityStatus(riskScore)
            )
        )

        insights.add(
            generateMalwareRecommendation(
                detectedThreats = detectedThreats
            )
        )

        insights.add(
            generateVpnRecommendation(
                vpnEnabled = vpnEnabled
            )
        )

        insights.add(
            generateRootRecommendation(
                rooted = rooted
            )
        )

        return insights
    }

    /**
     * Convert risk score to security status
     */
    private fun getSecurityStatus(
        riskScore: Int
    ): SecurityStatus {

        return when {

            riskScore >= 80 -> SecurityStatus.CRITICAL

            riskScore >= 60 -> SecurityStatus.DANGEROUS

            riskScore >= 40 -> SecurityStatus.WARNING

            riskScore >= 20 -> SecurityStatus.SAFE

            else -> SecurityStatus.SECURE
        }
    }
}
