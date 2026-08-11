package com.sentrix.security.vpn

import android.content.Context
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * VPNLeakDetector
 *
 * Enterprise-grade VPN leak detection component for SentriX.
 *
 * Responsibilities:
 *
 * - Detect DNS leaks.
 * - Detect IPv4 traffic bypass.
 * - Detect IPv6 leaks.
 * - Detect non-VPN interface traffic.
 * - Detect split-tunnel exposure.
 * - Detect unexpected DNS servers.
 * - Detect WebRTC exposure indicators.
 * - Detect unexpected public IP exposure.
 * - Detect routes outside the VPN tunnel.
 * - Maintain leak findings.
 * - Calculate leak severity.
 * - Publish reactive leak state.
 * - Maintain detection statistics.
 *
 * This class DOES NOT:
 *
 * - Modify routes.
 * - Disable IPv6.
 * - Change DNS settings.
 * - Kill network connections.
 * - Restart VPN.
 * - Block traffic.
 *
 * Enforcement belongs to VPNService, VPNManager,
 * VPNConnectionManager, or the appropriate routing/
 * firewall layer.
 *
 * Architecture:
 *
 *                   VPNService
 *                       |
 *                       v
 *                 VPNLeakDetector
 *                       |
 *       ┌───────────────┼────────────────┐
 *       ▼               ▼                ▼
 *    DNS Check      Route Check      Interface Check
 *       │               │                │
 *       └───────────────┼────────────────┘
 *                       ▼
 *                  Leak Findings
 *                       |
 *                       ▼
 *                 Security Engine
 */
class VPNLeakDetector(
    context: Context,
    private val configuration:
        VPNLeakDetectorConfiguration =
        VPNLeakDetectorConfiguration()
) {

    companion object {

        private const val TAG =
            "VPNLeakDetector"
    }

    /**
     * Application context.
     */
    private val applicationContext =
        context.applicationContext

    /**
     * Current leak state.
     */
    private val _state =
        MutableStateFlow(
            VPNLeakDetectionState()
        )

    /**
     * Public immutable leak state.
     */
    val state:
        StateFlow<VPNLeakDetectionState> =
        _state.asStateFlow()

    /**
     * Latest leak event.
     */
    private val _latestEvent =
        MutableStateFlow<VPNLeakEvent?>(
            null
        )

    /**
     * Public latest event.
     */
    val latestEvent:
        StateFlow<VPNLeakEvent?> =
        _latestEvent.asStateFlow()

    /**
     * Detection statistics.
     */
    private val statistics =
        VPNLeakDetectionStatisticsCounter()

    /**
     * Indicates whether detector is initialized.
     */
    @Volatile
    private var initialized =
        false

    /**
     * Performs detector initialization.
     */
    suspend fun initialize():
            VPNLeakDetectorOperationResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            if (
                initialized
            ) {

                return@withContext
                    VPNLeakDetectorOperationResult.success(
                        "VPN leak detector is already initialized."
                    )
            }

            initialized =
                true

            updateState {
                it.copy(
                    initialized =
                        true
                )
            }

            statistics.incrementInitializations()

            Log.i(
                TAG,
                "VPN leak detector initialized."
            )

            VPNLeakDetectorOperationResult.success(
                "VPN leak detector initialized successfully."
            )
        }

    /**
     * Performs a complete VPN leak scan.
     *
     * The caller supplies the observable network state.
     * This keeps the detector independent from a specific
     * VPN implementation.
     */
    suspend fun detectLeaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            VPNLeakDetectionResult =
        withContext(Dispatchers.Default) {

            checkCancellation()

            ensureInitialized()

            val findings =
                mutableListOf<VPNLeakFinding>()

            /**
             * DNS leak detection.
             */
            if (
                configuration
                    .detectDnsLeaks
            ) {

                findings +=
                    detectDnsLeaks(
                        snapshot
                    )
            }

            /**
             * IPv4 bypass detection.
             */
            if (
                configuration
                    .detectIpv4Leaks
            ) {

                findings +=
                    detectIpv4Leaks(
                        snapshot
                    )
            }

            /**
             * IPv6 leak detection.
             */
            if (
                configuration
                    .detectIpv6Leaks
            ) {

                findings +=
                    detectIpv6Leaks(
                        snapshot
                    )
            }

            /**
             * Interface bypass detection.
             */
            if (
                configuration
                    .detectInterfaceLeaks
            ) {

                findings +=
                    detectInterfaceLeaks(
                        snapshot
                    )
            }

            /**
             * Route leak detection.
             */
            if (
                configuration
                    .detectRouteLeaks
            ) {

                findings +=
                    detectRouteLeaks(
                        snapshot
                    )
            }

            /**
             * Split tunnel detection.
             */
            if (
                configuration
                    .detectSplitTunnel
            ) {

                findings +=
                    detectSplitTunnel(
                        snapshot
                    )
            }

            /**
             * WebRTC exposure detection.
             */
            if (
                configuration
                    .detectWebRtcExposure
            ) {

                findings +=
                    detectWebRtcExposure(
                        snapshot
                    )
            }

            /**
             * Public IP exposure detection.
             */
            if (
                configuration
                    .detectPublicIpExposure
            ) {

                findings +=
                    detectPublicIpExposure(
                        snapshot
                    )
            }

            val severity =
                calculateOverallSeverity(
                    findings
                )

            val result =
                VPNLeakDetectionResult(

                    scanId =
                        generateScanId(),

                    timestamp =
                        System.currentTimeMillis(),

                    leakDetected =
                        findings.isNotEmpty(),

                    severity =
                        severity,

                    findings =
                        findings,

                    checkedDnsServers =
                        snapshot
                            .dnsServers
                            .size,

                    checkedRoutes =
                        snapshot
                            .routes
                            .size,

                    checkedInterfaces =
                        snapshot
                            .networkInterfaces
                            .size
                )

            updateStateFromResult(
                result
            )

            statistics.incrementScans()

            if (
                findings.isNotEmpty()
            ) {

                statistics
                    .incrementLeakDetections()

                publishEvent(
                    VPNLeakEvent.LeakDetected(
                        timestamp =
                            System.currentTimeMillis(),

                        result =
                            result
                    )
                )

            } else {

                publishEvent(
                    VPNLeakEvent.NoLeakDetected(
                        timestamp =
                            System.currentTimeMillis()
                    )
                )
            }

            result
        }

    /**
     * Detects DNS leaks.
     */
    private fun detectDnsLeaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        val findings =
            mutableListOf<VPNLeakFinding>()

        if (
            snapshot.dnsServers.isEmpty()
        ) {

            findings +=
                VPNLeakFinding(
                    type =
                        VPNLeakType.DNS_LEAK,

                    severity =
                        VPNLeakSeverity.MEDIUM,

                    title =
                        "DNS configuration unavailable",

                    description =
                        "SentriX could not verify the DNS servers used by the active network.",

                    evidence =
                        "No DNS servers were reported.",

                    recommendation =
                        "Verify that DNS requests are routed through the VPN."
                )

            return findings
        }

        snapshot.dnsServers.forEach { dnsServer ->

            val normalized =
                normalizeIp(
                    dnsServer
                )

            val isAllowed =
                configuration
                    .trustedDnsServers
                    .contains(
                        normalized
                    )

            val isVpnDns =
                snapshot
                    .vpnDnsServers
                    .contains(
                        normalized
                    )

            if (
                !isAllowed &&
                !isVpnDns &&
                configuration
                    .flagUnknownDnsServers
            ) {

                findings +=
                    VPNLeakFinding(
                        type =
                            VPNLeakType.DNS_LEAK,

                        severity =
                            VPNLeakSeverity.HIGH,

                        title =
                            "Potential DNS leak",

                        description =
                            "DNS traffic may be using a resolver outside the expected VPN DNS path.",

                        evidence =
                            "Observed DNS server: $dnsServer",

                        recommendation =
                            "Ensure DNS requests are routed through the VPN tunnel."
                    )
            }
        }

        if (
            snapshot
                .dnsRequestsOutsideVpn > 0
        ) {

            findings +=
                VPNLeakFinding(
                    type =
                        VPNLeakType.DNS_LEAK,

                    severity =
                        VPNLeakSeverity.CRITICAL,

                    title =
                        "Confirmed DNS traffic bypass",

                    description =
                        "DNS requests were observed outside the VPN tunnel.",

                    evidence =
                        "${snapshot.dnsRequestsOutsideVpn} DNS requests bypassed the VPN.",

                    recommendation =
                        "Review VPN routing and DNS enforcement immediately."
                )
        }

        return findings
    }

    /**
     * Detects IPv4 traffic bypass.
     */
    private fun detectIpv4Leaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        if (
            snapshot
                .ipv4TrafficOutsideVpn <= 0
        ) {

            return emptyList()
        }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.IPV4_LEAK,

                severity =
                    VPNLeakSeverity.CRITICAL,

                title =
                    "IPv4 traffic bypass detected",

                description =
                    "IPv4 traffic was observed outside the VPN tunnel.",

                evidence =
                    "${snapshot.ipv4TrafficOutsideVpn} IPv4 flows bypassed the VPN.",

                recommendation =
                    "Verify VPN routes and kill-switch enforcement."
            )
        )
    }

    /**
     * Detects IPv6 leaks.
     */
    private fun detectIpv6Leaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        if (
            !snapshot.ipv6Available
        ) {

            return emptyList()
        }

        if (
            snapshot
                .ipv6TrafficOutsideVpn <= 0
        ) {

            return emptyList()
        }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.IPV6_LEAK,

                severity =
                    VPNLeakSeverity.CRITICAL,

                title =
                    "IPv6 traffic leak detected",

                description =
                    "IPv6 traffic was observed outside the protected VPN path.",

                evidence =
                    "${snapshot.ipv6TrafficOutsideVpn} IPv6 flows bypassed the VPN.",

                recommendation =
                    "Configure IPv6 routing through the VPN or enforce IPv6 protection."
            )
        )
    }

    /**
     * Detects traffic using non-VPN interfaces.
     */
    private fun detectInterfaceLeaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        val unexpected =
            snapshot.networkInterfaces
                .filter { networkInterface ->

                    networkInterface.isActive &&
                            networkInterface.isInternetCapable &&
                            !networkInterface.isVpnInterface
                }

        if (
            unexpected.isEmpty()
        ) {

            return emptyList()
        }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.INTERFACE_LEAK,

                severity =
                    VPNLeakSeverity.HIGH,

                title =
                    "Non-VPN network interface detected",

                description =
                    "An active Internet-capable interface exists outside the VPN interface.",

                evidence =
                    unexpected.joinToString(
                        separator =
                            ", "
                    ) {
                        it.name
                    },

                recommendation =
                    "Verify that Internet traffic cannot bypass the VPN interface."
            )
        )
    }

    /**
     * Detects route leakage.
     */
    private fun detectRouteLeaks(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        val unexpectedRoutes =
            snapshot.routes
                .filter { route ->

                    route.isInternetRoute &&
                            !route.usesVpnInterface
                }

        if (
            unexpectedRoutes.isEmpty()
        ) {

            return emptyList()
        }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.ROUTE_LEAK,

                severity =
                    VPNLeakSeverity.CRITICAL,

                title =
                    "Non-VPN Internet route detected",

                description =
                    "An Internet route exists outside the expected VPN interface.",

                evidence =
                    unexpectedRoutes.joinToString(
                        separator =
                            ", "
                    ) {
                        it.destination
                    },

                recommendation =
                    "Verify VPN route configuration and kill-switch behavior."
            )
        )
    }

    /**
     * Detects split tunneling.
     */
    private fun detectSplitTunnel(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        if (
            !snapshot
                .splitTunnelDetected
        ) {

            return emptyList()
        }

        val severity =
            if (
                snapshot
                    .unprotectedApplications
                    .isNotEmpty()
            ) {

                VPNLeakSeverity.HIGH

            } else {

                VPNLeakSeverity.MEDIUM
            }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.SPLIT_TUNNEL,

                severity =
                    severity,

                title =
                    "Split-tunnel exposure detected",

                description =
                    "Some traffic or applications may be operating outside the VPN tunnel.",

                evidence =
                    snapshot
                        .unprotectedApplications
                        .joinToString(),

                recommendation =
                    "Review per-application VPN routing and protected-app configuration."
            )
        )
    }

    /**
     * Detects WebRTC exposure indicators.
     */
    private fun detectWebRtcExposure(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        if (
            !snapshot
                .webRtcLocalAddressExposed &&
            !snapshot
                .webRtcPublicAddressExposed
        ) {

            return emptyList()
        }

        val exposure =
            buildString {

                if (
                    snapshot
                        .webRtcLocalAddressExposed
                ) {

                    append(
                        "Local address exposed. "
                    )
                }

                if (
                    snapshot
                        .webRtcPublicAddressExposed
                ) {

                    append(
                        "Public address exposed."
                    )
                }
            }

        return listOf(
            VPNLeakFinding(
                type =
                    VPNLeakType.WEBRTC_EXPOSURE,

                severity =
                    VPNLeakSeverity.HIGH,

                title =
                    "WebRTC address exposure detected",

                description =
                    "WebRTC may expose network addressing information outside the expected VPN protection boundary.",

                evidence =
                    exposure,

                recommendation =
                    "Review browser WebRTC behavior and VPN browser protection."
            )
        )
    }

    /**
     * Detects public IP exposure.
     */
    private fun detectPublicIpExposure(
        snapshot:
            VPNLeakTestSnapshot
    ):
            List<VPNLeakFinding> {

        val publicIp =
            snapshot.observedPublicIp
                ?: return emptyList()

        val expectedVpnIp =
            snapshot.expectedVpnPublicIp

        if (
            expectedVpnIp == null
        ) {

            return listOf(
                VPNLeakFinding(
                    type =
                        VPNLeakType.PUBLIC_IP_EXPOSURE,

                    severity =
                        VPNLeakSeverity.MEDIUM,

                    title =
                        "Public IP could not be verified",

                    description =
                        "The active VPN public IP could not be compared against an expected VPN address.",

                    evidence =
                        "Observed public IP: $publicIp",

                    recommendation =
                        "Verify public IP routing through the VPN."
                )
            )
        }

        if (
            normalizeIp(
                publicIp
            ) !=
            normalizeIp(
                expectedVpnIp
            )
        ) {

            return listOf(
                VPNLeakFinding(
                    type =
                        VPNLeakType.PUBLIC_IP_EXPOSURE,

                    severity =
                        VPNLeakSeverity.CRITICAL,

                    title =
                        "Public IP exposure detected",

                    description =
                        "The observed public IP differs from the expected VPN public IP.",

                    evidence =
                        "Observed: $publicIp, Expected VPN: $expectedVpnIp",

                    recommendation =
                        "Verify VPN routing and external IP protection."
                )
            )
        }

        return emptyList()
    }

    /**
     * Calculates overall severity.
     */
    private fun calculateOverallSeverity(
        findings:
            List<VPNLeakFinding>
    ):
            VPNLeakSeverity {

        return findings
            .maxByOrNull {
                it.severity.ordinal
            }
            ?.severity
            ?: VPNLeakSeverity.NONE
    }

    /**
     * Updates StateFlow from a scan result.
     */
    private fun updateStateFromResult(
        result:
            VPNLeakDetectionResult
    ) {

        updateState {
            it.copy(

                lastScanId =
                    result.scanId,

                lastScanAt =
                    result.timestamp,

                leakDetected =
                    result.leakDetected,

                severity =
                    result.severity,

                findingCount =
                    result.findings.size,

                criticalFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNLeakSeverity.CRITICAL
                    },

                highFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNLeakSeverity.HIGH
                    },

                mediumFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNLeakSeverity.MEDIUM
                    },

                lowFindingCount =
                    result.findings.count {
                        it.severity ==
                                VPNLeakSeverity.LOW
                    }
            )
        }
    }

    /**
     * Publishes leak event.
     */
    private fun publishEvent(
        event:
            VPNLeakEvent
    ) {

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
     * Updates detector state.
     */
    private fun updateState(
        transform:
            (VPNLeakDetectionState) ->
            VPNLeakDetectionState
    ) {

        _state.value =
            transform(
                _state.value
            )
    }

    /**
     * Returns current leak state.
     */
    fun getState():
            VPNLeakDetectionState {

        return _state.value
    }

    /**
     * Returns whether a leak is currently detected.
     */
    fun isLeakDetected():
            Boolean {

        return _state.value.leakDetected
    }

    /**
     * Returns current leak severity.
     */
    fun getSeverity():
            VPNLeakSeverity {

        return _state.value.severity
    }

    /**
     * Returns whether immediate attention is required.
     */
    fun requiresImmediateAttention():
            Boolean {

        return _state.value.severity ==
                VPNLeakSeverity.CRITICAL
    }

    /**
     * Returns detector statistics.
     */
    fun getStatistics():
            VPNLeakDetectionStatistics {

        return statistics.snapshot()
    }

    /**
     * Performs a quick DNS leak check.
     */
    suspend fun checkDnsServers(
        dnsServers:
            List<String>,
        vpnDnsServers:
            List<String>
    ):
            VPNLeakDetectionResult {

        val snapshot =
            VPNLeakTestSnapshot(

                dnsServers =
                    dnsServers,

                vpnDnsServers =
                    vpnDnsServers
            )

        return detectLeaks(
            snapshot
        )
    }

    /**
     * Performs a simple public IP comparison.
     */
    suspend fun checkPublicIp(
        observedPublicIp:
            String,
        expectedVpnPublicIp:
            String
    ):
            VPNLeakDetectionResult {

        val snapshot =
            VPNLeakTestSnapshot(

                observedPublicIp =
                    observedPublicIp,

                expectedVpnPublicIp =
                    expectedVpnPublicIp
            )

        return detectLeaks(
            snapshot
        )
    }

    /**
     * Performs a route leak check.
     */
    suspend fun checkRoutes(
        routes:
            List<VPNRouteInfo>
    ):
            VPNLeakDetectionResult {

        val snapshot =
            VPNLeakTestSnapshot(
                routes =
                    routes
            )

        return detectLeaks(
            snapshot
        )
    }

    /**
     * Normalizes an IP address.
     */
    private fun normalizeIp(
        address:
            String
    ):
            String {

        return try {

            InetAddress
                .getByName(
                    address.trim()
                )
                .hostAddress
                ?.lowercase()
                ?: address
                    .trim()
                    .lowercase()

        } catch (
            _: Exception
        ) {

            address
                .trim()
                .lowercase()
        }
    }

    /**
     * Ensures initialization.
     */
    private fun ensureInitialized() {

        check(
            initialized
        ) {
            "VPNLeakDetector has not been initialized."
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
                "VPN leak detection operation was cancelled."
            )
        }
    }

    /**
     * Releases resources.
     */
    fun close() {

        initialized =
            false

        _state.value =
            VPNLeakDetectionState()

        _latestEvent.value =
            null

        Log.i(
            TAG,
            "VPNLeakDetector closed."
        )
    }

    /**
     * Generates scan identifier.
     */
    private fun generateScanId():
            String {

        return "VPN_LEAK_SCAN_" +
                java.util.UUID
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
 * Configuration for VPN leak detection.
 */
data class VPNLeakDetectorConfiguration(

    /**
     * Enable DNS leak detection.
     */
    val detectDnsLeaks:
        Boolean = true,

    /**
     * Enable IPv4 leak detection.
     */
    val detectIpv4Leaks:
        Boolean = true,

    /**
     * Enable IPv6 leak detection.
     */
    val detectIpv6Leaks:
        Boolean = true,

    /**
     * Enable interface leak detection.
     */
    val detectInterfaceLeaks:
        Boolean = true,

    /**
     * Enable route leak detection.
     */
    val detectRouteLeaks:
        Boolean = true,

    /**
     * Enable split-tunnel detection.
     */
    val detectSplitTunnel:
        Boolean = true,

    /**
     * Enable WebRTC exposure detection.
     */
    val detectWebRtcExposure:
        Boolean = true,

    /**
     * Enable public IP comparison.
     */
    val detectPublicIpExposure:
        Boolean = true,

    /**
     * Flag DNS servers not known to the VPN.
     */
    val flagUnknownDnsServers:
        Boolean = true,

    /**
     * DNS servers trusted by SentriX.
     */
    val trustedDnsServers:
        Set<String> =
        emptySet()
)

/**
 * Input snapshot for leak detection.
 */
data class VPNLeakTestSnapshot(

    /**
     * DNS servers currently observed.
     */
    val dnsServers:
        List<String> =
        emptyList(),

    /**
     * DNS servers expected through the VPN.
     */
    val vpnDnsServers:
        List<String> =
        emptyList(),

    /**
     * Number of DNS requests outside VPN.
     */
    val dnsRequestsOutsideVpn:
        Long = 0,

    /**
     * Number of IPv4 flows outside VPN.
     */
    val ipv4TrafficOutsideVpn:
        Long = 0,

    /**
     * Whether IPv6 is available.
     */
    val ipv6Available:
        Boolean = false,

    /**
     * Number of IPv6 flows outside VPN.
     */
    val ipv6TrafficOutsideVpn:
        Long = 0,

    /**
     * Network interfaces.
     */
    val networkInterfaces:
        List<VPNNetworkInterfaceInfo> =
        emptyList(),

    /**
     * Network routes.
     */
    val routes:
        List<VPNRouteInfo> =
        emptyList(),

    /**
     * Split tunnel detected.
     */
    val splitTunnelDetected:
        Boolean = false,

    /**
     * Applications not protected by VPN.
     */
    val unprotectedApplications:
        List<String> =
        emptyList(),

    /**
     * WebRTC local address exposure.
     */
    val webRtcLocalAddressExposed:
        Boolean = false,

    /**
     * WebRTC public address exposure.
     */
    val webRtcPublicAddressExposed:
        Boolean = false,

    /**
     * Observed public IP.
     */
    val observedPublicIp:
        String? = null,

    /**
     * Expected VPN public IP.
     */
    val expectedVpnPublicIp:
        String? = null
)

/**
 * Network interface information.
 */
data class VPNNetworkInterfaceInfo(

    val name:
        String,

    val address:
        String? = null,

    val isActive:
        Boolean = false,

    val isVpnInterface:
        Boolean = false,

    val isInternetCapable:
        Boolean = false
)

/**
 * Route information.
 */
data class VPNRouteInfo(

    val destination:
        String,

    val gateway:
        String? = null,

    val interfaceName:
        String? = null,

    val isInternetRoute:
        Boolean = false,

    val usesVpnInterface:
        Boolean = false
)

/**
 * Leak finding.
 */
data class VPNLeakFinding(

    val type:
        VPNLeakType,

    val severity:
        VPNLeakSeverity,

    val title:
        String,

    val description:
        String,

    val evidence:
        String,

    val recommendation:
        String
)

/**
 * Leak type.
 */
enum class VPNLeakType {

    DNS_LEAK,

    IPV4_LEAK,

    IPV6_LEAK,

    INTERFACE_LEAK,

    ROUTE_LEAK,

    SPLIT_TUNNEL,

    WEBRTC_EXPOSURE,

    PUBLIC_IP_EXPOSURE
}

/**
 * Leak severity.
 */
enum class VPNLeakSeverity {

    NONE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Complete leak detection result.
 */
data class VPNLeakDetectionResult(

    val scanId:
        String,

    val timestamp:
        Long,

    val leakDetected:
        Boolean,

    val severity:
        VPNLeakSeverity,

    val findings:
        List<VPNLeakFinding>,

    val checkedDnsServers:
        Int,

    val checkedRoutes:
        Int,

    val checkedInterfaces:
        Int
)

/**
 * Reactive leak detector state.
 */
data class VPNLeakDetectionState(

    val initialized:
        Boolean = false,

    val lastScanId:
        String? = null,

    val lastScanAt:
        Long? = null,

    val leakDetected:
        Boolean = false,

    val severity:
        VPNLeakSeverity =
        VPNLeakSeverity.NONE,

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

    val latestEvent:
        VPNLeakEvent? = null
)

/**
 * Leak detector events.
 */
sealed class VPNLeakEvent {

    abstract val timestamp:
        Long

    /**
     * One or more leaks were detected.
     */
    data class LeakDetected(
        override val timestamp:
            Long,
        val result:
            VPNLeakDetectionResult
    ) : VPNLeakEvent()

    /**
     * No leak was detected.
     */
    data class NoLeakDetected(
        override val timestamp:
            Long
    ) : VPNLeakEvent()
}

/**
 * Leak detector operation result.
 */
data class VPNLeakDetectorOperationResult(

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
                VPNLeakDetectorOperationResult {

            return VPNLeakDetectorOperationResult(
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
                VPNLeakDetectorOperationResult {

            return VPNLeakDetectorOperationResult(
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
 * Leak detection statistics.
 */
data class VPNLeakDetectionStatistics(

    val initializations:
        Long,

    val scans:
        Long,

    val leakDetections:
        Long,

    val totalFindings:
        Long,

    val criticalFindings:
        Long,

    val highFindings:
        Long,

    val mediumFindings:
        Long,

    val lowFindings:
        Long
)

/**
 * Thread-safe leak detection statistics.
 */
private class VPNLeakDetectionStatisticsCounter {

    private val initializations =
        AtomicLong(0)

    private val scans =
        AtomicLong(0)

    private val leakDetections =
        AtomicLong(0)

    private val totalFindings =
        AtomicLong(0)

    private val criticalFindings =
        AtomicLong(0)

    private val highFindings =
        AtomicLong(0)

    private val mediumFindings =
        AtomicLong(0)

    private val lowFindings =
        AtomicLong(0)

    fun incrementInitializations() {
        initializations.incrementAndGet()
    }

    fun incrementScans() {
        scans.incrementAndGet()
    }

    fun incrementLeakDetections() {
        leakDetections.incrementAndGet()
    }

    fun snapshot():
            VPNLeakDetectionStatistics {

        return VPNLeakDetectionStatistics(

            initializations =
                initializations.get(),

            scans =
                scans.get(),

            leakDetections =
                leakDetections.get(),

            totalFindings =
                totalFindings.get(),

            criticalFindings =
                criticalFindings.get(),

            highFindings =
                highFindings.get(),

            mediumFindings =
                mediumFindings.get(),

            lowFindings =
                lowFindings.get()
        )
    }
}
