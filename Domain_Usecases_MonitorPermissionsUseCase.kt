package com.sentrix.domain.usecases

/**
 * MonitorPermissionsUseCase
 *
 * Responsible for monitoring
 * application permissions and
 * identifying potentially risky
 * permission requests.
 *
 * Permission monitoring helps:
 * - Detect excessive permissions
 * - Identify privacy risks
 * - Improve device security
 * - Reduce attack surface
 * - Protect sensitive data
 *
 * Used by:
 * - PermissionManager
 * - PrivacyProtectionEngine
 * - SecurityDashboard
 * - CyberDefenseManager
 *
 * Responsibilities:
 * - Analyze permissions
 * - Detect dangerous permissions
 * - Generate permission reports
 * - Identify suspicious apps
 * - Assess permission risks
 */
class MonitorPermissionsUseCase {

    /**
     * Monitors application permissions.
     */
    operator fun invoke(
        permissions: List<AppPermission>
    ): PermissionMonitoringResult {

        val dangerousPermissions =
            permissions.count {
                it.permissionRisk ==
                    PermissionRisk.HIGH
            }

        val suspiciousApps =
            permissions.count {
                it.permissionRisk ==
                    PermissionRisk.CRITICAL
            }

        return PermissionMonitoringResult(
            monitoredAt =
                System.currentTimeMillis(),

            totalPermissions =
                permissions.size,

            dangerousPermissions =
                dangerousPermissions,

            suspiciousApps =
                suspiciousApps,

            securityStatus =
                determineSecurityStatus(
                    dangerousPermissions,
                    suspiciousApps
                ),

            permissions =
                permissions
        )
    }

    /**
     * Determines permission
     * security status.
     */
    private fun determineSecurityStatus(
        dangerousPermissions: Int,
        suspiciousApps: Int
    ): PermissionSecurityStatus {

        return when {

            suspiciousApps >= 5 ->
                PermissionSecurityStatus.CRITICAL

            dangerousPermissions >= 10 ->
                PermissionSecurityStatus.HIGH_RISK

            dangerousPermissions >= 5 ->
                PermissionSecurityStatus.MODERATE_RISK

            else ->
                PermissionSecurityStatus.SAFE
        }
    }
}

/**
 * PermissionMonitoringResult
 *
 * Represents permission
 * monitoring results.
 */
data class PermissionMonitoringResult(

    /**
     * Monitoring timestamp.
     */
    val monitoredAt: Long,

    /**
     * Total permissions analyzed.
     */
    val totalPermissions: Int,

    /**
     * Dangerous permissions found.
     */
    val dangerousPermissions: Int,

    /**
     * Suspicious applications.
     */
    val suspiciousApps: Int,

    /**
     * Overall security status.
     */
    val securityStatus:
        PermissionSecurityStatus,

    /**
     * Permission details.
     */
    val permissions:
        List<AppPermission>
)

/**
 * AppPermission
 *
 * Represents application
 * permission information.
 */
data class AppPermission(

    /**
     * Application identifier.
     */
    val appId: String,

    /**
     * Application name.
     */
    val appName: String,

    /**
     * Permission name.
     */
    val permissionName: String,

    /**
     * Permission granted status.
     */
    val isGranted: Boolean,

    /**
     * Permission risk level.
     */
    val permissionRisk:
        PermissionRisk
)

/**
 * Permission risk levels.
 */
enum class PermissionRisk {

    /**
     * Safe permission.
     */
    LOW,

    /**
     * Moderate risk permission.
     */
    MEDIUM,

    /**
     * Dangerous permission.
     */
    HIGH,

    /**
     * Critical permission risk.
     */
    CRITICAL
}

/**
 * Permission security status.
 */
enum class PermissionSecurityStatus {

    /**
     * Device is safe.
     */
    SAFE,

    /**
     * Moderate permission risks.
     */
    MODERATE_RISK,

    /**
     * High permission risks.
     */
    HIGH_RISK,

    /**
     * Critical permission risks.
     */
    CRITICAL
}
