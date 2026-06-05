package com.sentrix.domain.models

/**
 * AppInfo
 *
 * Represents information about an installed,
 * monitored, or analyzed application within
 * the SentriX cybersecurity platform.
 *
 * The model contains application metadata,
 * security attributes, installation details,
 * permissions, and threat assessment results.
 *
 * Used by:
 * - AppScanner
 * - MalwareDetectionEngine
 * - ApplicationMonitor
 * - PermissionAnalyzer
 * - SecurityDashboard
 * - ThreatAnalysisManager
 * - DeviceProtectionService
 * - BehavioralAnalysisEngine
 */
data class AppInfo(

    /**
     * Unique application identifier.
     */
    val appId: String,

    /**
     * Application display name.
     */
    val appName: String,

    /**
     * Package name or bundle identifier.
     */
    val packageName: String,

    /**
     * Application version name.
     */
    val versionName: String,

    /**
     * Application version code.
     */
    val versionCode: Long,

    /**
     * Application category.
     */
    val category: AppCategory,

    /**
     * Developer or publisher name.
     */
    val developerName: String? = null,

    /**
     * Application source.
     */
    val installationSource: InstallationSource =
        InstallationSource.UNKNOWN,

    /**
     * Indicates whether the application
     * is currently installed.
     */
    val isInstalled: Boolean = true,

    /**
     * Indicates whether the application
     * is currently enabled.
     */
    val isEnabled: Boolean = true,

    /**
     * Indicates whether the application
     * is classified as a system app.
     */
    val isSystemApp: Boolean = false,

    /**
     * Indicates whether the application
     * is currently running.
     */
    val isRunning: Boolean = false,

    /**
     * Installation timestamp.
     */
    val installedAt: Long = 0L,

    /**
     * Last update timestamp.
     */
    val lastUpdatedAt: Long = 0L,

    /**
     * Application size in bytes.
     */
    val appSizeBytes: Long = 0L,

    /**
     * Security score assigned to
     * the application.
     */
    val securityScore: Int = 0,

    /**
     * Risk level assigned after
     * security analysis.
     */
    val riskLevel: AppRiskLevel =
        AppRiskLevel.LOW,

    /**
     * Malware detection status.
     */
    val malwareStatus: MalwareStatus =
        MalwareStatus.NOT_SCANNED,

    /**
     * Number of detected threats.
     */
    val detectedThreats: Int = 0,

    /**
     * Number of suspicious behaviors
     * identified during analysis.
     */
    val suspiciousBehaviors: Int = 0,

    /**
     * Requested permissions.
     */
    val permissions: List<String> =
        emptyList(),

    /**
     * Dangerous permissions identified
     * during analysis.
     */
    val dangerousPermissions: List<String> =
        emptyList(),

    /**
     * Security warnings generated
     * for the application.
     */
    val securityWarnings: List<String> =
        emptyList(),

    /**
     * Supported activities or modules.
     */
    val components: List<String> =
        emptyList(),

    /**
     * Additional application metadata.
     */
    val metadata: Map<String, String> =
        emptyMap()
)

/**
 * Application category classifications.
 */
enum class AppCategory {

    /**
     * Productivity application.
     */
    PRODUCTIVITY,

    /**
     * Communication application.
     */
    COMMUNICATION,

    /**
     * Social networking application.
     */
    SOCIAL,

    /**
     * Financial or banking application.
     */
    FINANCE,

    /**
     * Shopping or e-commerce application.
     */
    SHOPPING,

    /**
     * Entertainment application.
     */
    ENTERTAINMENT,

    /**
     * Gaming application.
     */
    GAMING,

    /**
     * Education application.
     */
    EDUCATION,

    /**
     * Health and fitness application.
     */
    HEALTH,

    /**
     * Security application.
     */
    SECURITY,

    /**
     * Business application.
     */
    BUSINESS,

    /**
     * Developer tool application.
     */
    DEVELOPMENT,

    /**
     * Uncategorized application.
     */
    OTHER
}

/**
 * Application installation source.
 */
enum class InstallationSource {

    /**
     * Google Play Store.
     */
    PLAY_STORE,

    /**
     * Apple App Store.
     */
    APP_STORE,

    /**
     * Enterprise application store.
     */
    ENTERPRISE_STORE,

    /**
     * Side-loaded application.
     */
    SIDELOADED,

    /**
     * Installed from APK or package file.
     */
    PACKAGE_INSTALLER,

    /**
     * Unknown installation source.
     */
    UNKNOWN
}

/**
 * Application risk indicators.
 */
enum class AppRiskLevel {

    /**
     * Low-risk application.
     */
    LOW,

    /**
     * Medium-risk application.
     */
    MEDIUM,

    /**
     * High-risk application.
     */
    HIGH,

    /**
     * Critical-risk application.
     */
    CRITICAL
}

/**
 * Malware analysis status.
 */
enum class MalwareStatus {

    /**
     * Application has not been scanned.
     */
    NOT_SCANNED,

    /**
     * Scan is currently in progress.
     */
    SCANNING,

    /**
     * Application is clean.
     */
    CLEAN,

    /**
     * Suspicious activity detected.
     */
    SUSPICIOUS,

    /**
     * Malware detected.
     */
    MALICIOUS,

    /**
     * Application quarantined.
     */
    QUARANTINED
}
