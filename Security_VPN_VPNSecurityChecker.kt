package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNSecurityChecker
 *
 * Central security posture checker for the SentriX VPN subsystem.
 *
 * Responsibilities:
 *
 * - Evaluate VPN security posture.
 * - Check VPN connection health.
 * - Check VPN state.
 * - Check network health.
 * - Check active threats.
 * - Check VPN leaks.
 * - Check connection security.
 * - Check configuration security.
 * - Check DNS protection.
 * - Check IPv6 protection.
 * - Check route protection.
 * - Calculate security score.
 * - Determine overall security level.
 * - Generate security recommendations.
 * - Publish security-check events.
 * - Maintain security-check statistics.
 *
 * This class DOES NOT:
 *
 * - Start or stop the VPN.
 * - Change VPN configuration.
 * - Modify network routes.
 * - Block network traffic.
 * - Resolve threats.
 * - Fix VPN leaks.
 *
 * Enforcement belongs to:
 *
 * VPNManager
 * VPNService
 * FirewallEngine
 * VPNConnectionManager
 * VPNConfigurationManager
 *
 * Architecture:
 *
 *                    VPN Subsystem
 *                         |
 *       ┌─────────────────┼─────────────────┐
 *       ▼                 ▼                 ▼
 * VPNStateMonitor   VPNNetworkMonitor   VPNThreatMonitor
 *       │                 │                 │
 *       └─────────────────┼─────────────────┘
 *                         ▼
 *                  VPNLeakDetector
 *                         │
 *                         ▼
 *                  VPNSecurityChecker
 *                         │
 *          ┌──────────────┼──────────────┐
 *          ▼              ▼              ▼
 *       Score          Findings       Recommendations
 *          │              │              │
 *          └──────────────┼──────────────┘
 *                         ▼
 *                 SentriX Security UI
 */
class VPNSecurityChecker(
    context: Context,
    private val configuration:
        VPNSecurityCheckerConfiguration =
        VPNSecurityCheckerConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNSecurityChecker"
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Initialization state.
     */
    private val initialized =
        AtomicBoolean(false)

    /**
     * Latest security assessment.
     */
    private val _state =
        MutableStateFlow(
            VPNSecurityCheckerState()
        )

    /**
     * Public immutable security state.
     */
    val state:
        StateFlow<VPNSecurityCheckerState> =
        _state.asStateFlow()

    /**
     * Latest security event.
     */
    private val _latestEvent =
        MutableStateFlow<VPNSecurityEvent?>(
            null
        )

    /**
     * Public latest event.
     */
    val latestEvent:
        StateFlow<VPNSecurityEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Security check statistics.
     */
    private val statistics =
        VPNSecurityCheckerStatisticsCounter()

    /**
     * Initializes the security checker.
     */
    suspend fun initialize():
            VPNSecurityCheckerOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized.get()
            ) {

                return@withContext
                    VPNSecurityCheckerOperationResult.success(
                        "VPN security checker is already initialized."
                    )
            }

            initialized.set(
                true
            )

            updateState {
                it.copy(
                    initialized =
                        true
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN security checker initialized."
            )

            VPNSecurityCheckerOperationResult.success(
                "VPN security checker initialized successfully."
            )
        }

    /**
     * Performs a complete VPN security assessment.
     *
     * The caller provides the current state of the
     * different VPN security components.
     */
    suspend fun performSecurityCheck(
        input:
            VPNSecurityCheckInput
    ):
            VPNSecurityCheckResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            statistics.incrementChecks()

            val findings =
                mutableListOf<VPNSecurityFinding>()

            /*
             * 1. VPN state check.
             */
            findings +=
                checkVpnState(
                    input
                )

            /*
             * 2. VPN health check.
             */
            findings +=
                checkVpnHealth(
                    input
                )

            /*
             * 3. Network health check.
             */
            findings +=
                checkNetworkHealth(
                    input
                )

            /*
             * 4. Threat check.
             */
            findings +=
                checkThreats(
                    input
                )

            /*
             * 5. Leak check.
             */
            findings +=
                checkLeaks(
                    input
                )

            /*
             * 6. DNS security check.
             */
            findings +=
                checkDnsSecurity(
                    input
                )

            /*
             * 7. IPv6 security check.
             */
            findings +=
                checkIpv6Security(
                    input
                )

            /*
             * 8. Route security check.
             */
            findings +=
                checkRouteSecurity(
                    input
                )

            /*
             * 9. Connection security check.
             */
            findings +=
                checkConnectionSecurity(
                    input
                )

            /*
             * 10. Configuration security check.
             */
            findings +=
                checkConfigurationSecurity(
                    input
                )

            /*
             * 11. Kill-switch posture.
             */
            findings +=
                checkKillSwitch(
                    input
                )

            /*
             * 12. Encryption posture.
             */
            findings +=
                checkEncryption(
                    input
                )

            val score =
                calculateSecurityScore(
                    findings
                )

            val level =
                determineSecurityLevel(
                    score,
                    findings
                )

            val recommendations =
                generateRecommendations(
                    findings
                )

            val result =
                VPNSecurityCheckResult(

                    checkId =
                        generateCheckId(),

                    timestamp =
                        System.currentTimeMillis(),

                    score =
                        score,

                    level =
                        level,

                    findings =
                        findings,

                    recommendations =
                        recommendations,

                    secure =
                        level ==
                                VPNSecurityLevel.SECURE ||
                                level ==
                                VPNSecurityLevel.EXCELLENT,

                    vpnConnected =
                        input
                            .vpnState
                            .currentStatus ==
                            VPNStatus.CONNECTED,

                    activeThreats =
                        input
                            .threatState
                            .activeThreatCount,

                    leakDetected =
                        input
                            .leakState
                            .leakDetected
                )

            updateStateFromResult(
                result
            )

            statistics
                .recordFindings(
                    findings
                )

            publishAssessmentEvent(
                result
            )

            result
        }

    /**
     * Checks VPN lifecycle state.
     */
    private fun checkVpnState(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        return when (
            input.vpnState.currentStatus
        ) {

            VPNStatus.CONNECTED -> {

                emptyList()
            }

            VPNStatus.CONNECTING,
            VPNStatus.STARTING -> {

                listOf(
                    VPNSecurityFinding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_STATE,

                        severity =
                            VPNSecuritySeverity.MEDIUM,

                        title =
                            "VPN is not fully connected",

                        description =
                            "The VPN is currently establishing its protected connection.",

                        scoreImpact =
                            15,

                        recommendation =
                            "Wait until the VPN reaches a connected state."
                    )
                )
            }

            VPNStatus.PERMISSION_REQUIRED -> {

                listOf(
                    VPNSecurityFinding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_STATE,

                        severity =
                            VPNSecuritySeverity.HIGH,

                        title =
                            "VPN permission is required",

                        description =
                            "The VPN does not have the required Android VPN permission.",

                        scoreImpact =
                            30,

                        recommendation =
                            "Grant VPN permission and reconnect the VPN."
                    )
                )
            }

            VPNStatus.ERROR -> {

                listOf(
                    VPNSecurityFinding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_STATE,

                        severity =
                            VPNSecuritySeverity.CRITICAL,

                        title =
                            "VPN is in an error state",

                        description =
                            input
                                .vpnState
                                .lastError
                                ?: "The VPN reported an error.",

                        scoreImpact =
                            45,

                        recommendation =
                            "Investigate the VPN error and restore the protected connection."
                    )
                )
            }

            VPNStatus.STOPPING -> {

                listOf(
                    VPNSecurityFinding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_STATE,

                        severity =
                            VPNSecuritySeverity.HIGH,

                        title =
                            "VPN is stopping",

                        description =
                            "The VPN protection layer is currently shutting down.",

                        scoreImpact =
                            30,

                        recommendation =
                            "Reconnect the VPN before transmitting sensitive traffic."
                    )
                )
            }

            VPNStatus.DISCONNECTED -> {

                listOf(
                    VPNSecurityFinding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_STATE,

                        severity =
                            VPNSecuritySeverity.CRITICAL,

                        title =
                            "VPN is disconnected",

                        description =
                            "The device currently has no active VPN protection.",

                        scoreImpact =
                            50,

                        recommendation =
                            "Reconnect the VPN before using untrusted networks."
                    )
                )
            }
        }
    }

    /**
     * Checks VPN health.
     */
    private fun checkVpnHealth(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        return when (
            input.vpnState.health
        ) {

            VPNHealthStatus.HEALTHY ->
                emptyList()

            VPNHealthStatus.UNKNOWN -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.MEDIUM,

                        title =
                            "VPN health is unknown",

                        description =
                            "SentriX could not establish the current VPN health state.",

                        impact =
                            10,

                        recommendation =
                            "Perform another VPN health check."
                    )
                )
            }

            VPNHealthStatus.DEGRADED -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.MEDIUM,

                        title =
                            "VPN health is degraded",

                        description =
                            input
                                .vpnState
                                .healthReason
                                ?: "The VPN connection is degraded.",

                        impact =
                            20,

                        recommendation =
                            "Investigate VPN connectivity and traffic health."
                    )
                )
            }

            VPNHealthStatus.STALE -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.HIGH,

                        title =
                            "VPN connection is stale",

                        description =
                            "The VPN connection has remained in a stale state longer than expected.",

                        impact =
                            30,

                        recommendation =
                            "Re-establish the VPN connection."
                    )
                )
            }

            VPNHealthStatus.UNHEALTHY -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.CRITICAL,

                        title =
                            "VPN is unhealthy",

                        description =
                            input
                                .vpnState
                                .healthReason
                                ?: "VPN health checks indicate an unhealthy connection.",

                        impact =
                            40,

                        recommendation =
                            "Restore VPN health before relying on the tunnel."
                    )
                )
            }

            VPNHealthStatus.PERMISSION_REQUIRED -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.HIGH,

                        title =
                            "VPN permission is unavailable",

                        description =
                            "The VPN cannot provide protection without required permission.",

                        impact =
                            30,

                        recommendation =
                            "Grant the required VPN permission."
                    )
                )
            }

            VPNHealthStatus.STARTING -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.MEDIUM,

                        title =
                            "VPN is starting",

                        description =
                            "The VPN security tunnel has not completed initialization.",

                        impact =
                            15,

                        recommendation =
                            "Wait for VPN initialization to complete."
                    )
                )
            }

            VPNHealthStatus.STOPPING -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.HIGH,

                        title =
                            "VPN protection is stopping",

                        description =
                            "VPN protection is currently being terminated.",

                        impact =
                            30,

                        recommendation =
                            "Reconnect the VPN before continuing sensitive network activity."
                    )
                )
            }

            VPNHealthStatus.DISCONNECTED -> {

                listOf(
                    finding(
                        category =
                            VPNSecurityFindingCategory
                                .VPN_HEALTH,

                        severity =
                            VPNSeverity.CRITICAL,

                        title =
                            "VPN health indicates disconnection",

                        description =
                            "The VPN health monitor reports that protection is unavailable.",

                        impact =
                            45,

                        recommendation =
                            "Reconnect the VPN."
                    )
                )
            }
        }
    }

    /**
     * Checks network health.
     */
    private fun checkNetworkHealth(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        return when (
            input.networkState.health
        ) {

            VPNNetworkHealth.HEALTHY ->
                emptyList()

            VPNNetworkHealth.UNKNOWN -> {

                listOf(
                    finding(
                        category =
                            VPNSeverityCategory.NETWORK,

                        severity =
                            VPNSeverity.MEDIUM,

                        title =
                            "Network health is unknown",

                        description =
                            "Current VPN network health could not be confidently established.",

                        impact =
                            10,

                        recommendation =
                            "Perform another network health check."
                    )
                )
            }

            VPNNetworkHealth.DEGRADED -> {

                listOf(
                    finding(
                        category =
                            VPNSeverityCategory.NETWORK,

                        severity =
                            VPNSeverity.MEDIUM,

                        title =
                            "VPN network is degraded",

                        description =
                            input
                                .networkState
                                .healthReason
                                ?: "Network activity indicates degraded conditions.",

                        impact =
                            20,

                        recommendation =
                            "Investigate network connectivity and VPN traffic."
                    )
                )
            }

            VPNNetworkHealth.DISCONNECTED -> {

                listOf(
                    finding(
                        category =
                            VPNSeverityCategory.NETWORK,

                        severity =
                            VPNSeverity.CRITICAL,

                        title =
                            "VPN network transport is unavailable",

                        description =
                            "The network transport required by the VPN is unavailable.",

                        impact =
                            40,

                        recommendation =
                            "Restore network connectivity and recheck the VPN."
                    )
                )
            }
        }
    }

    /**
     * Checks active VPN threats.
     */
    private fun checkThreats(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val threatState =
            input.threatState

        val findings =
            mutableListOf<VPNSecurityFinding>()

        if (
            threatState.criticalThreatCount > 0
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.THREAT,

                    severity =
                        VPNSeverity.CRITICAL,

                    title =
                        "Critical VPN threats detected",

                    description =
                        "${threatState.criticalThreatCount} critical VPN threat(s) are currently active.",

                    impact =
                        45,

                    recommendation =
                        "Block or isolate the affected traffic and investigate the threat."
                )
        }

        if (
            threatState.highThreatCount > 0
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.THREAT,

                    severity =
                        VPNSeverity.HIGH,

                    title =
                        "High-risk VPN threats detected",

                    description =
                        "${threatState.highThreatCount} high-severity VPN threat(s) are active.",

                    impact =
                        30,

                    recommendation =
                        "Review the affected endpoints and enforce the appropriate security policy."
                )
        }

        if (
            threatState.mediumThreatCount > 0
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.THREAT,

                    severity =
                        VPNSeverity.MEDIUM,

                    title =
                        "Medium-risk VPN activity detected",

                    description =
                        "${threatState.mediumThreatCount} medium-severity threat(s) are active.",

                    impact =
                        15,

                    recommendation =
                        "Review suspicious network activity."
                )
        }

        return findings
    }

    /**
     * Checks VPN leak state.
     */
    private fun checkLeaks(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val leakState =
            input.leakState

        if (
            !leakState.leakDetected
        ) {

            return emptyList()
        }

        val severity =
            when (
                leakState.severity
            ) {

                VPNLeakSeverity.CRITICAL ->
                    VPNSeverity.CRITICAL

                VPNLeakSeverity.HIGH ->
                    VPNSeverity.HIGH

                VPNLeakSeverity.MEDIUM ->
                    VPNSeverity.MEDIUM

                VPNLeakSeverity.LOW ->
                    VPNSeverity.LOW

                VPNLeakSeverity.NONE ->
                    VPNSeverity.LOW
            }

        val impact =
            when (
                leakState.severity
            ) {

                VPNLeakSeverity.CRITICAL ->
                    50

                VPNLeakSeverity.HIGH ->
                    35

                VPNLeakSeverity.MEDIUM ->
                    20

                VPNLeakSeverity.LOW ->
                    10

                VPNLeakSeverity.NONE ->
                    0
            }

        return listOf(
            finding(
                category =
                    VPNSeverityCategory.LEAK,

                severity =
                    severity,

                title =
                    "VPN leak detected",

                description =
                    "${leakState.findingCount} VPN leak finding(s) were detected.",

                impact =
                    impact,

                recommendation =
                    "Review the leak findings and restore complete VPN traffic protection."
            )
        )
    }

    /**
     * Checks DNS protection.
     */
    private fun checkDnsSecurity(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val findings =
            mutableListOf<VPNSecurityFinding>()

        if (
            input
                .networkSnapshot
                .dnsRequestsOutsideVpn > 0
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.DNS,

                    severity =
                        VPNSeverity.CRITICAL,

                    title =
                        "DNS requests bypass VPN",

                    description =
                        "${input.networkSnapshot.dnsRequestsOutsideVpn} DNS request(s) were observed outside the VPN.",

                    impact =
                        40,

                    recommendation =
                        "Ensure all DNS traffic is routed through the protected VPN path."
                )
        }

        if (
            input
                .networkSnapshot
                .dnsFailures >
            configuration
                .maximumAllowedDnsFailures
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.DNS,

                    severity =
                        VPNSeverity.MEDIUM,

                    title =
                        "Elevated DNS failures",

                    description =
                        "${input.networkSnapshot.dnsFailures} DNS failures were observed.",

                    impact =
                        10,

                    recommendation =
                        "Verify DNS resolver availability and VPN DNS configuration."
                )
        }

        return findings
    }

    /**
     * Checks IPv6 protection.
     */
    private fun checkIpv6Security(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        if (
            !input
                .networkSnapshot
                .ipv6Available
        ) {

            return emptyList()
        }

        if (
            input
                .networkSnapshot
                .ipv6TrafficOutsideVpn <= 0
        ) {

            return emptyList()
        }

        return listOf(
            finding(
                category =
                    VPNSeverityCategory.IPV6,

                severity =
                    VPNSeverity.CRITICAL,

                title =
                    "IPv6 traffic is bypassing VPN",

                description =
                    "${input.networkSnapshot.ipv6TrafficOutsideVpn} IPv6 flow(s) were observed outside the VPN.",

                impact =
                    40,

                recommendation =
                    "Protect IPv6 traffic through the VPN or enforce an appropriate IPv6 policy."
            )
        )
    }

    /**
     * Checks VPN routing.
     */
    private fun checkRouteSecurity(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val unprotectedRoutes =
            input
                .networkSnapshot
                .routes
                .count {
                    it.isInternetRoute &&
                            !it.usesVpnInterface
                }

        if (
            unprotectedRoutes <= 0
        ) {

            return emptyList()
        }

        return listOf(
            finding(
                category =
                    VPNSeverityCategory.ROUTING,

                severity =
                    VPNSeverity.CRITICAL,

                title =
                    "Unprotected Internet routes detected",

                description =
                    "$unprotectedRoutes Internet route(s) do not use the VPN interface.",

                impact =
                    45,

                recommendation =
                    "Review VPN routing and prevent Internet traffic from bypassing the tunnel."
            )
        )
    }

    /**
     * Checks active network connections.
     */
    private fun checkConnectionSecurity(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val count =
            input
                .networkState
                .activeConnectionCount

        if (
            count <=
            configuration
                .maximumAllowedConnections
        ) {

            return emptyList()
        }

        return listOf(
            finding(
                category =
                    VPNSeverityCategory.CONNECTIONS,

                severity =
                    VPNSeverity.MEDIUM,

                title =
                    "Unusually high connection count",

                description =
                    "$count active VPN network connections were observed.",

                impact =
                    10,

                recommendation =
                    "Review active connections for unexpected or automated traffic."
            )
        )
    }

    /**
     * Checks VPN configuration posture.
     */
    private fun checkConfigurationSecurity(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val configurationState =
            input.configurationState

        val findings =
            mutableListOf<VPNSecurityFinding>()

        if (
            !configurationState.valid
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.CONFIGURATION,

                    severity =
                        VPNSeverity.HIGH,

                    title =
                        "VPN configuration is invalid",

                    description =
                        configurationState
                            .validationMessage
                            ?: "The VPN configuration failed validation.",

                    impact =
                        30,

                    recommendation =
                        "Correct the VPN configuration before relying on the tunnel."
                )
        }

        if (
            !configurationState
                .encryptionEnabled
        ) {

            findings +=
                finding(
                    category =
                        VPNSeverityCategory.ENCRYPTION,

                    severity =
                        VPNSeverity.CRITICAL,

                    title =
                        "VPN encryption is not enabled",

                    description =
                        "The current VPN security configuration does not report encryption as enabled.",

                    impact =
                        45,

                    recommendation =
                        "Enable a secure VPN encryption configuration."
                )
        }

        return findings
    }

    /**
     * Checks kill-switch posture.
     */
    private fun checkKillSwitch(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        if (
            !configuration
                .requireKillSwitch
        ) {

            return emptyList()
        }

        if (
            input
                .configurationState
                .killSwitchEnabled
        ) {

            return emptyList()
        }

        return listOf(
            finding(
                category =
                    VPNSeverityCategory.KILL_SWITCH,

                severity =
                    VPNSeverity.HIGH,

                title =
                    "VPN kill switch is disabled",

                description =
                    "Network traffic may remain available if the VPN tunnel disconnects.",

                impact =
                    25,

                recommendation =
                    "Enable the VPN kill switch for stronger leak protection."
            )
        )
    }

    /**
     * Checks encryption posture.
     */
    private fun checkEncryption(
        input:
            VPNSecurityCheckInput
    ):
            List<VPNSecurityFinding> {

        val encryption =
            input
                .configurationState
                .encryption

        if (
            !input
                .configurationState
                .encryptionEnabled
        ) {

            return emptyList()
        }

        if (
            encryption ==
            VPNEncryptionProtocol.UNKNOWN
        ) {

            return listOf(
                finding(
                    category =
                        VPNSeverityCategory.ENCRYPTION,

                    severity =
                        VPNSeverity.MEDIUM,

                    title =
                        "VPN encryption protocol is unknown",

                    description =
                        "The VPN reports encryption enabled but its protocol could not be verified.",

                    impact =
                        10,

                    recommendation =
                        "Verify the active VPN encryption protocol."
                )
            )
        }

        if (
            encryption ==
            VPNEncryptionProtocol.WEAK
        ) {

            return listOf(
                finding(
                    category =
                        VPNSeverityCategory.ENCRYPTION,

                    severity =
                        VPNSeverity.HIGH,

                    title =
                        "Weak VPN encryption detected",

                    description =
                        "The configured VPN encryption does not meet the configured security policy.",

                    impact =
                        25,

                    recommendation =
                        "Use a modern, secure VPN encryption protocol."
                )
            )
        }

        return emptyList()
    }

    /**
     * Converts findings into a 0-100 security score.
     *
     * 100 = strongest posture.
     * 0 = severely compromised/unprotected posture.
     */
    private fun calculateSecurityScore(
        findings:
            List<VPNSecurityFinding>
    ):
            Int {

        val totalImpact =
            findings.sumOf {
                it.scoreImpact
            }

        return (
            100 -
                    totalImpact
            )
            .coerceIn(
                0,
                100
            )
    }

    /**
     * Determines overall security level.
     */
    private fun determineSecurityLevel(
        score:
            Int,
        findings:
            List<VPNSecurityFinding>
    ):
            VPNSecurityLevel {

        val critical =
            findings.any {
                it.severity ==
                        VPNSecuritySeverity.CRITICAL
            }

        if (
            critical
        ) {

            return VPNSecurityLevel.CRITICAL
        }

        return when {

            score >= 90 ->
                VPNSecurityLevel.EXCELLENT

            score >= 75 ->
                VPNSecurityLevel.SECURE

            score >= 55 ->
                VPNSecurityLevel.MODERATE

            score >= 30 ->
                VPNSecurityLevel.WEAK

            else ->
                VPNSecurityLevel.CRITICAL
        }
    }

    /**
     * Generates security recommendations.
     */
    private fun generateRecommendations(
        findings:
            List<VPNSecurityFinding>
    ):
            List<VPNSecurityRecommendation> {

        return findings
            .sortedByDescending {
                it.scoreImpact
            }
            .distinctBy {
                it.recommendation
            }
            .mapIndexed { index, finding ->

                VPNSecurityRecommendation(

                    id =
                        "VPN_REC_" +
                                UUID
                                    .randomUUID()
                                    .toString()
                                    .take(8)
                                    .uppercase(),

                    priority =
                        when {
                            index == 0 ->
                                VPNSecurityRecommendationPriority.CRITICAL

                            index < 3 ->
                                VPNSecurityRecommendationPriority.HIGH

                            else ->
                                VPNSecurityRecommendationPriority.NORMAL
                        },

                    title =
                        "Improve VPN security",

                    description =
                        finding.recommendation,

                    category =
                        finding.category
                )
            }
    }

    /**
     * Creates a security finding.
     */
    private fun finding(
        category:
            VPNSecurityFindingCategory,
        severity:
            VPNSecuritySeverity,
        title:
            String,
        description:
            String,
        impact:
            Int,
        recommendation:
            String
    ):
            VPNSecurityFinding {

        return VPNSecurityFinding(

            id =
                "VPN_FINDING_" +
                        UUID
                            .randomUUID()
                            .toString()
                            .take(12)
                            .uppercase(),

            category =
                category,

            severity =
                severity,

            title =
                title,

            description =
                description,

            scoreImpact =
                impact,

            recommendation =
                recommendation
        )
    }

    /**
     * Updates StateFlow from the assessment.
     */
    private fun updateStateFromResult(
        result:
            VPNSecurityCheckResult
    ) {

        updateState {
            it.copy(

                lastCheckId =
                    result.checkId,

                lastCheckAt =
                    result.timestamp,

                score =
                    result.score,

                level =
                    result.level,

                secure =
                    result.secure,

                findingCount =
                    result.findings.size,

                criticalFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNSecuritySeverity.CRITICAL
                    },

                highFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNSecuritySeverity.HIGH
                    },

                mediumFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNSecuritySeverity.MEDIUM
                    },

                lowFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNSecuritySeverity.LOW
                    },

                activeThreatCount =
                    result.activeThreats,

                leakDetected =
                    result.leakDetected
            )
        }
    }

    /**
     * Publishes security assessment event.
     */
    private fun publishAssessmentEvent(
        result:
            VPNSecurityCheckResult
    ) {

        val event =
            if (
                result.level ==
                VPNSecurityLevel.CRITICAL
            ) {

                VPNSecurityEvent.CriticalRisk(
                    timestamp =
                        System.currentTimeMillis(),

                    result =
                        result
                )

            } else {

                VPNSecurityEvent.AssessmentCompleted(
                    timestamp =
                        System.currentTimeMillis(),

                    result =
                        result
                )
            }

        _latestEvent.value =
            event

        updateState {
            it.copy(
                latestEvent =
                    event
            )
        }
    }

    /**
     * Updates internal state.
     */
    private fun updateState(
        transform:
            (VPNSecurityCheckerState) ->
            VPNSecurityCheckerState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Returns latest security result.
     */
    fun getState():
            VPNSecurityCheckerState {

        return _state.value
    }

    /**
     * Returns current security score.
     */
    fun getSecurityScore():
            Int {

        return _state.value.score
    }

    /**
     * Returns current security level.
     */
    fun getSecurityLevel():
            VPNSecurityLevel {

        return _state.value.level
    }

    /**
     * Returns whether VPN posture is secure.
     */
    fun isSecure():
            Boolean {

        return _state.value.secure
    }

    /**
     * Returns whether immediate action is required.
     */
    fun requiresImmediateAttention():
            Boolean {

        return _state.value.level ==
                VPNSecurityLevel.CRITICAL
    }

    /**
     * Returns checker statistics.
     */
    fun getStatistics():
            VPNSecurityCheckerStatistics {

        return statistics.snapshot()
    }

    /**
     * Clears the latest event.
     */
    fun clearLatestEvent() {

        _latestEvent.value =
            null

        updateState {
            it.copy(
                latestEvent =
                    null
            )
        }
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized.get()
        ) {
            "VPNSecurityChecker has not been initialized."
        }
    }

    /**
     * Coroutine cancellation support.
     */
    private suspend fun checkCancellation() {

        if (
            !kotlinx.coroutines
                .currentCoroutineContext()
                .isActive
        ) {

            throw CancellationException(
                "VPN security check was cancelled."
            )
        }
    }

    /**
     * Closes the security checker.
     */
    fun close() {

        initialized.set(
            false
        )

        _state.value =
            VPNSecurityCheckerState()

        _latestEvent.value =
            null

        Log.i(
            TAG,
            "VPNSecurityChecker closed."
        )
    }

    /**
     * Generates assessment ID.
     */
    private fun generateCheckId():
            String {

        return "VPN_SECURITY_" +
                UUID
                    .randomUUID()
                    .toString()
                    .replace(
                        "-",
                        ""
                    )
                    .take(20)
                    .uppercase()
    }
}

/**
 * Complete input required for a VPN security assessment.
 */
data class VPNSecurityCheckInput(

    /**
     * Current VPN state.
     */
    val vpnState:
        VPNMonitorState,

    /**
     * Current VPN network state.
     */
    val networkState:
        VPNNetworkMonitorState,

    /**
     * Current VPN threat state.
     */
    val threatState:
        VPNThreatMonitorState,

    /**
     * Current VPN leak state.
     */
    val leakState:
        VPNLeakDetectionState,

    /**
     * Current network snapshot.
     */
    val networkSnapshot:
        VPNLeakTestSnapshot,

    /**
     * Current VPN configuration security state.
     */
    val configurationState:
        VPNSecurityConfigurationState
)

/**
 * VPN configuration security state.
 */
data class VPNSecurityConfigurationState(

    /**
     * Whether configuration passed validation.
     */
    val valid:
        Boolean = true,

    /**
     * Configuration validation message.
     */
    val validationMessage:
        String? = null,

    /**
     * Whether encryption is enabled.
     */
    val encryptionEnabled:
        Boolean = true,

    /**
     * Encryption protocol.
     */
    val encryption:
        VPNEncryptionProtocol =
        VPNEncryptionProtocol.STRONG,

    /**
     * Kill switch state.
     */
    val killSwitchEnabled:
        Boolean = true
)

/**
 * VPN encryption classification.
 */
enum class VPNEncryptionProtocol {

    STRONG,

    MODERN,

    WEAK,

    UNKNOWN
}

/**
 * VPN security finding.
 */
data class VPNSecurityFinding(

    val id:
        String =
        UUID
            .randomUUID()
            .toString(),

    val category:
        VPNSecurityFindingCategory,

    val severity:
        VPNSecuritySeverity,

    val title:
        String,

    val description:
        String,

    /**
     * Score reduction caused by this finding.
     */
    val scoreImpact:
        Int,

    val recommendation:
        String
)

/**
 * Security finding categories.
 */
enum class VPNSecurityFindingCategory {

    VPN_STATE,

    VPN_HEALTH,

    NETWORK,

    THREAT,

    LEAK,

    DNS,

    IPV6,

    ROUTING,

    CONNECTIONS,

    CONFIGURATION,

    KILL_SWITCH,

    ENCRYPTION
}

/**
 * VPN security severity.
 */
enum class VPNSecuritySeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Alias used internally for concise category references.
 */
private object VPNSeverityCategory {

    val NETWORK =
        VPNSecurityFindingCategory.NETWORK

    val THREAT =
        VPNSecurityFindingCategory.THREAT

    val LEAK =
        VPNSecurityFindingCategory.LEAK

    val DNS =
        VPNSecurityFindingCategory.DNS

    val IPV6 =
        VPNSecurityFindingCategory.IPV6

    val ROUTING =
        VPNSecurityFindingCategory.ROUTING

    val CONNECTIONS =
        VPNSecurityFindingCategory.CONNECTIONS

    val CONFIGURATION =
        VPNSecurityFindingCategory.CONFIGURATION

    val KILL_SWITCH =
        VPNSecurityFindingCategory.KILL_SWITCH

    val ENCRYPTION =
        VPNSecurityFindingCategory.ENCRYPTION
}

/**
 * Alias used internally for severity references.
 */
private object VPNSeverity {

    val LOW =
        VPNSecuritySeverity.LOW

    val MEDIUM =
        VPNSecuritySeverity.MEDIUM

    val HIGH =
        VPNSecuritySeverity.HIGH

    val CRITICAL =
        VPNSecuritySeverity.CRITICAL
}

/**
 * Overall VPN security level.
 */
enum class VPNSecurityLevel {

    EXCELLENT,

    SECURE,

    MODERATE,

    WEAK,

    CRITICAL
}

/**
 * Security recommendation.
 */
data class VPNSecurityRecommendation(

    val id:
        String,

    val priority:
        VPNSecurityRecommendationPriority,

    val title:
        String,

    val description:
        String,

    val category:
        VPNSecurityFindingCategory
)

/**
 * Recommendation priority.
 */
enum class VPNSecurityRecommendationPriority {

    NORMAL,

    HIGH,

    CRITICAL
}

/**
 * Complete VPN security assessment.
 */
data class VPNSecurityCheckResult(

    val checkId:
        String,

    val timestamp:
        Long,

    val score:
        Int,

    val level:
        VPNSecurityLevel,

    val findings:
        List<VPNSecurityFinding>,

    val recommendations:
        List<VPNSecurityRecommendation>,

    val secure:
        Boolean,

    val vpnConnected:
        Boolean,

    val activeThreats:
        Int,

    val leakDetected:
        Boolean
)

/**
 * Reactive VPN security state.
 */
data class VPNSecurityCheckerState(

    val initialized:
        Boolean = false,

    val lastCheckId:
        String? = null,

    val lastCheckAt:
        Long? = null,

    val score:
        Int = 0,

    val level:
        VPNSecurityLevel =
        VPNSecurityLevel.CRITICAL,

    val secure:
        Boolean = false,

    val findingCount:
        Int = 0,

    val criticalFindingCount:
        Int = 0,

    val highFindingCount:
        Int = 0,

    val mediumFindingCount:
        Int = 0,

    val lowFindingCount:
        Int = 0,

    val activeThreatCount:
        Int = 0,

    val leakDetected:
        Boolean = false,

    val latestEvent:
        VPNSecurityEvent? = null
)

/**
 * VPN security events.
 */
sealed class VPNSecurityEvent {

    abstract val timestamp:
        Long

    /**
     * Normal security assessment completed.
     */
    data class AssessmentCompleted(
        override val timestamp:
            Long,

        val result:
            VPNSecurityCheckResult
    ) : VPNSecurityEvent()

    /**
     * Critical VPN security risk detected.
     */
    data class CriticalRisk(
        override val timestamp:
            Long,

        val result:
            VPNSecurityCheckResult
    ) : VPNSecurityEvent()
}

/**
 * VPN security checker configuration.
 */
data class VPNSecurityCheckerConfiguration(

    /**
     * Maximum DNS failures allowed before raising
     * a security finding.
     */
    val maximumAllowedDnsFailures:
        Int = 10,

    /**
     * Maximum active connections considered normal.
     */
    val maximumAllowedConnections:
        Int = 500,

    /**
     * Whether kill switch should be required.
     */
    val requireKillSwitch:
        Boolean = true
)

/**
 * Generic operation result.
 */
data class VPNSecurityCheckerOperationResult(

    val success:
        Boolean,

    val message:
        String,

    val error:
        String? = null
) {

    companion object {

        fun success(
            message:
                String
        ):
                VPNSecurityCheckerOperationResult {

            return VPNSecurityCheckerOperationResult(
                success =
                    true,

                message =
                    message
            )
        }

        fun failure(
            message:
                String,
            error:
                String? = null
        ):
                VPNSecurityCheckerOperationResult {

            return VPNSecurityCheckerOperationResult(
                success =
                    false,

                message =
                    message,

                error =
                    error
            )
        }
    }
}

/**
 * VPN security checker statistics.
 */
data class VPNSecurityCheckerStatistics(

    val initializations:
        Long,

    val checks:
        Long,

    val criticalFindings:
        Long,

    val highFindings:
        Long,

    val mediumFindings:
        Long,

    val lowFindings:
        Long,

    val totalFindings:
        Long
)

/**
 * Thread-safe security checker statistics.
 */
private class VPNSecurityCheckerStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val checks =
        AtomicLong(0)

    private val criticalFindings =
        AtomicLong(0)

    private val highFindings =
        AtomicLong(0)

    private val mediumFindings =
        AtomicLong(0)

    private val lowFindings =
        AtomicLong(0)

    private val totalFindings =
        AtomicLong(0)

    fun incrementInitializations() {

        initializations.incrementAndGet()
    }

    fun incrementChecks() {

        checks.incrementAndGet()
    }

    fun recordFindings(
        findings:
            List<VPNSecurityFinding>
    ) {

        if (
            findings.isEmpty()
        ) {

            return
        }

        totalFindings.addAndGet(
            findings.size.toLong()
        )

        findings.forEach {

            when (
                it.severity
            ) {

                VPNSecuritySeverity.CRITICAL ->
                    criticalFindings.incrementAndGet()

                VPNSecuritySeverity.HIGH ->
                    highFindings.incrementAndGet()

                VPNSecuritySeverity.MEDIUM ->
                    mediumFindings.incrementAndGet()

                VPNSecuritySeverity.LOW ->
                    lowFindings.incrementAndGet()
            }
        }
    }

    fun snapshot():
            VPNSecurityCheckerStatistics {

        return VPNSecurityCheckerStatistics(

            initializations =
                initializations.get(),

            checks =
                checks.get(),

            criticalFindings =
                criticalFindings.get(),

            highFindings =
                highFindings.get(),

            mediumFindings =
                mediumFindings.get(),

            lowFindings =
                lowFindings.get(),

            totalFindings =
                totalFindings.get()
        )
    }
}
