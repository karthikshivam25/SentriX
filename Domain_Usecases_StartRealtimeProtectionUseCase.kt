package com.sentrix.domain.usecases

import com.sentrix.domain.models.RealtimeProtectionStatus
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.RealtimeProtectionRepository

/**
 * StartRealtimeProtectionUseCase
 *
 * Responsible for initializing and activating
 * SentriX real-time protection services.
 *
 * This use case enables continuous monitoring,
 * threat detection, malware protection,
 * intrusion prevention, phishing protection,
 * and automated security response mechanisms.
 *
 * It serves as the primary entry point for
 * activating the real-time cyber defense
 * capabilities of the SentriX platform.
 *
 * Used by:
 * - RealtimeProtectionEngine
 * - SecurityManager
 * - CyberDefenseManager
 * - ApplicationStartupManager
 * - DeviceProtectionService
 * - SecurityDashboard
 * - ThreatMonitoringService
 * - SecurityOrchestrator
 *
 * Responsibilities:
 * - Start protection services
 * - Enable security monitoring
 * - Initialize threat detection
 * - Activate protection modules
 * - Verify protection readiness
 * - Generate protection status
 */
class StartRealtimeProtectionUseCase(
    private val repository: RealtimeProtectionRepository
) {

    /**
     * Starts SentriX real-time protection.
     *
     * @return RealtimeProtectionStartResult
     */
    suspend operator fun invoke():
        RealtimeProtectionStartResult {

        val protectionModules =
            repository.getProtectionModules()

        val initializedModules =
            protectionModules.filter {
                repository.initializeModule(
                    it.moduleId
                )
            }

        val protectionStatus =
            RealtimeProtectionStatus(
                isProtectionActive = true,
                isMonitoringEnabled = true,
                isThreatDetectionActive = true,
                isFirewallActive =
                    initializedModules.any {
                        it.type ==
                            ProtectionModuleType.FIREWALL
                    },
                isVpnProtectionActive =
                    initializedModules.any {
                        it.type ==
                            ProtectionModuleType.VPN
                    },
                isMalwareShieldActive =
                    initializedModules.any {
                        it.type ==
                            ProtectionModuleType.MALWARE_PROTECTION
                    },
                isPhishingProtectionActive =
                    initializedModules.any {
                        it.type ==
                            ProtectionModuleType.PHISHING_PROTECTION
                    },
                isIntrusionDetectionActive =
                    initializedModules.any {
                        it.type ==
                            ProtectionModuleType.INTRUSION_DETECTION
                    },
                currentThreatLevel =
                    ThreatLevel.LOW,
                enabledProtectionModules =
                    initializedModules.map {
                        it.moduleName
                    }
            )

        return RealtimeProtectionStartResult(
            startedAt =
                System.currentTimeMillis(),
            success =
                initializedModules.isNotEmpty(),
            initializedModules =
                initializedModules,
            failedModules =
                protectionModules -
                    initializedModules.toSet(),
            protectionStatus =
                protectionStatus,
            recommendations =
                generateRecommendations(
                    initializedModules.size,
                    protectionModules.size
                )
        )
    }

    /**
     * Generates startup recommendations.
     */
    private fun generateRecommendations(
        initializedCount: Int,
        totalCount: Int
    ): List<String> {

        return when {

            initializedCount == totalCount ->
                listOf(
                    "All protection modules initialized successfully",
                    "Real-time protection fully operational"
                )

            initializedCount > 0 ->
                listOf(
                    "Some protection modules failed initialization",
                    "Review module configuration",
                    "Verify required permissions"
                )

            else ->
                listOf(
                    "Protection startup failed",
                    "Verify security service configuration",
                    "Review system logs"
                )
        }
    }
}

/**
 * RealtimeProtectionStartResult
 *
 * Represents the outcome of
 * real-time protection startup.
 */
data class RealtimeProtectionStartResult(

    /**
     * Startup timestamp.
     */
    val startedAt: Long,

    /**
     * Indicates whether startup
     * completed successfully.
     */
    val success: Boolean,

    /**
     * Successfully initialized modules.
     */
    val initializedModules:
        List<ProtectionModule>,

    /**
     * Failed protection modules.
     */
    val failedModules:
        List<ProtectionModule>,

    /**
     * Current protection status.
     */
    val protectionStatus:
        RealtimeProtectionStatus,

    /**
     * Startup recommendations.
     */
    val recommendations:
        List<String>
)

/**
 * ProtectionModule
 *
 * Represents a real-time
 * protection component.
 */
data class ProtectionModule(

    /**
     * Unique module identifier.
     */
    val moduleId: String,

    /**
     * Module name.
     */
    val moduleName: String,

    /**
     * Module type.
     */
    val type: ProtectionModuleType,

    /**
     * Module version.
     */
    val version: String,

    /**
     * Indicates whether the module
     * is enabled.
     */
    val isEnabled: Boolean
)

/**
 * Supported protection modules.
 */
enum class ProtectionModuleType {

    /**
     * Firewall protection.
     */
    FIREWALL,

    /**
     * Malware protection.
     */
    MALWARE_PROTECTION,

    /**
     * Intrusion detection.
     */
    INTRUSION_DETECTION,

    /**
     * Phishing protection.
     */
    PHISHING_PROTECTION,

    /**
     * Ransomware protection.
     */
    RANSOMWARE_PROTECTION,

    /**
     * VPN protection.
     */
    VPN,

    /**
     * AI threat detection.
     */
    AI_PROTECTION,

    /**
     * Zero Trust protection.
     */
    ZERO_TRUST
}
