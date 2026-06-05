package com.sentrix.domain.usecases

import com.sentrix.domain.models.RealtimeProtectionStatus
import com.sentrix.domain.models.ThreatLevel
import com.sentrix.domain.repositories.RealtimeProtectionRepository

/**
 * StopRealtimeProtectionUseCase
 *
 * Responsible for safely stopping and disabling
 * SentriX real-time protection services.
 *
 * This use case gracefully shuts down active
 * protection modules, monitoring services,
 * threat detection engines, and automated
 * response components while ensuring system
 * stability and preserving audit information.
 *
 * Used by:
 * - RealtimeProtectionEngine
 * - SecurityManager
 * - CyberDefenseManager
 * - ApplicationShutdownManager
 * - DeviceProtectionService
 * - SecurityDashboard
 * - SystemMaintenanceManager
 * - SecurityOrchestrator
 *
 * Responsibilities:
 * - Stop protection services
 * - Disable security monitoring
 * - Shutdown protection modules
 * - Preserve security state
 * - Record shutdown events
 * - Generate shutdown status
 */
class StopRealtimeProtectionUseCase(
    private val repository: RealtimeProtectionRepository
) {

    /**
     * Stops SentriX real-time protection.
     *
     * @return RealtimeProtectionStopResult
     */
    suspend operator fun invoke():
        RealtimeProtectionStopResult {

        val protectionModules =
            repository.getProtectionModules()

        val stoppedModules =
            mutableListOf<ProtectionModule>()

        val failedModules =
            mutableListOf<ProtectionModule>()

        protectionModules.forEach { module ->

            val stopped =
                repository.stopModule(
                    module.moduleId
                )

            if (stopped) {
                stoppedModules += module
            } else {
                failedModules += module
            }
        }

        val protectionStatus =
            RealtimeProtectionStatus(
                isProtectionActive = false,
                isMonitoringEnabled = false,
                isThreatDetectionActive = false,
                isFirewallActive = false,
                isVpnProtectionActive = false,
                isMalwareShieldActive = false,
                isPhishingProtectionActive = false,
                isRansomwareProtectionActive = false,
                isIntrusionDetectionActive = false,
                currentThreatLevel =
                    ThreatLevel.LOW,
                enabledProtectionModules =
                    emptyList(),
                disabledProtectionModules =
                    protectionModules.map {
                        it.moduleName
                    }
            )

        return RealtimeProtectionStopResult(
            stoppedAt =
                System.currentTimeMillis(),
            success =
                failedModules.isEmpty(),
            stoppedModules =
                stoppedModules,
            failedModules =
                failedModules,
            protectionStatus =
                protectionStatus,
            recommendations =
                generateRecommendations(
                    failedModules.isEmpty()
                )
        )
    }

    /**
     * Generates shutdown recommendations.
     */
    private fun generateRecommendations(
        successfulShutdown: Boolean
    ): List<String> {

        return if (successfulShutdown) {

            listOf(
                "Real-time protection stopped successfully",
                "Monitoring services disabled",
                "System is no longer actively protected"
            )

        } else {

            listOf(
                "Some protection modules failed to stop",
                "Review module shutdown logs",
                "Verify service termination state"
            )
        }
    }
}

/**
 * RealtimeProtectionStopResult
 *
 * Represents the outcome of
 * real-time protection shutdown.
 */
data class RealtimeProtectionStopResult(

    /**
     * Shutdown timestamp.
     */
    val stoppedAt: Long,

    /**
     * Indicates whether shutdown
     * completed successfully.
     */
    val success: Boolean,

    /**
     * Successfully stopped modules.
     */
    val stoppedModules:
        List<ProtectionModule>,

    /**
     * Modules that failed to stop.
     */
    val failedModules:
        List<ProtectionModule>,

    /**
     * Current protection status.
     */
    val protectionStatus:
        RealtimeProtectionStatus,

    /**
     * Shutdown recommendations.
     */
    val recommendations:
        List<String>
)
