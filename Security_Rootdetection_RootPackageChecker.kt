package com.sentrix.security.rootdetection

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager

/**
 * RootPackageChecker
 *
 * Detects installed applications that are commonly associated with
 * root management, privilege escalation, or modified Android
 * environments.
 *
 * Responsibilities:
 *
 * - Check known root-management package identifiers.
 * - Collect package metadata.
 * - Safely handle Android package-visibility restrictions.
 * - Return structured evidence for higher-level analysis.
 *
 * This class does NOT:
 *
 * - determine the final root status
 * - calculate device risk
 * - inspect filesystem binaries
 * - inspect system properties
 * - inspect mount configuration
 * - generate security reports
 *
 * Architecture:
 *
 * RootDetectionService
 *        ↓
 * RootDetectionManager
 *        ↓
 * RootChecker
 *        ↓
 * RootPackageChecker
 *        ↓
 * PackageManager
 */
class RootPackageChecker(
    private val context: Context
) {

    /**
     * Android PackageManager used to inspect installed applications.
     */
    private val packageManager: PackageManager =
        context.packageManager

    /**
     * Known root-management packages.
     *
     * Package names are treated as detection indicators only.
     *
     * IMPORTANT:
     * This list should be maintained independently from the
     * detection logic so that new package identifiers can be
     * added without changing the checker implementation.
     */
    private val knownRootPackages = setOf(

        // Magisk
        "com.topjohnwu.magisk",

        // SuperSU
        "eu.chainfire.supersu",

        // Superuser
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su",

        // Common legacy root-management identifiers
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.devadvance.rootcloak"
    )

    /**
     * Performs a complete scan for known root-management packages.
     *
     * @return RootPackageScanResult containing detected packages
     *         and scan metadata.
     */
    fun scan(): RootPackageScanResult {

        val detectedPackages = mutableListOf<RootPackageEvidence>()

        knownRootPackages.forEach { packageName ->

            val packageInfo = getPackageInfoSafely(
                packageName
            )

            if (packageInfo != null) {

                detectedPackages += createEvidence(
                    packageInfo
                )
            }
        }

        return RootPackageScanResult(
            detectedPackages = detectedPackages,
            packagesChecked = knownRootPackages.size,
            scanCompleted = true,
            scanTimestamp = System.currentTimeMillis()
        )
    }

    /**
     * Checks whether at least one known root-management package
     * is installed.
     *
     * This is intentionally a lightweight operation.
     */
    fun hasRootPackage(): Boolean {

        return knownRootPackages.any { packageName ->
            isPackageInstalled(packageName)
        }
    }

    /**
     * Returns all detected root-management package names.
     */
    fun getDetectedPackageNames(): List<String> {

        return knownRootPackages.filter { packageName ->
            isPackageInstalled(packageName)
        }
    }

    /**
     * Checks a specific package name.
     *
     * This method is useful when SentriX receives a package name
     * from another security subsystem.
     */
    fun checkPackage(
        packageName: String
    ): RootPackageEvidence? {

        if (packageName.isBlank()) {
            return null
        }

        val packageInfo = getPackageInfoSafely(
            packageName
        )

        return packageInfo?.let {
            createEvidence(it)
        }
    }

    /**
     * Determines whether a package is part of the known root package
     * database.
     *
     * This does NOT check whether the package is installed.
     */
    fun isKnownRootPackage(
        packageName: String
    ): Boolean {

        return knownRootPackages.contains(
            packageName.trim()
        )
    }

    /**
     * Returns a defensive copy of the configured root package list.
     */
    fun getKnownRootPackages(): Set<String> {

        return knownRootPackages.toSet()
    }

    /**
     * Returns the number of known packages currently installed.
     */
    fun getDetectedPackageCount(): Int {

        return knownRootPackages.count { packageName ->
            isPackageInstalled(packageName)
        }
    }

    /**
     * Checks whether a package is installed.
     *
     * Android package visibility rules can cause some packages to
     * appear unavailable even when they exist.
     *
     * Therefore, false means "not observable through this check",
     * rather than absolute proof of absence.
     */
    fun isPackageInstalled(
        packageName: String
    ): Boolean {

        return getPackageInfoSafely(
            packageName
        ) != null
    }

    /**
     * Retrieves PackageInfo safely across Android API levels.
     */
    @Suppress("DEPRECATION")
    private fun getPackageInfoSafely(
        packageName: String
    ): PackageInfo? {

        return try {

            if (android.os.Build.VERSION.SDK_INT >=
                android.os.Build.VERSION_CODES.TIRAMISU
            ) {

                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.PackageInfoFlags.of(0)
                )

            } else {

                packageManager.getPackageInfo(
                    packageName,
                    0
                )
            }

        } catch (_: PackageManager.NameNotFoundException) {

            null

        } catch (_: SecurityException) {

            null

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Converts Android PackageInfo into SentriX-specific evidence.
     */
    private fun createEvidence(
        packageInfo: PackageInfo
    ): RootPackageEvidence {

        val applicationInfo =
            packageInfo.applicationInfo

        val packageName =
            packageInfo.packageName

        val applicationLabel = try {

            applicationInfo?.let {
                packageManager.getApplicationLabel(it)
                    .toString()
            }

        } catch (_: Exception) {

            null
        }

        val versionName =
            packageInfo.versionName

        val versionCode =
            getVersionCode(packageInfo)

        return RootPackageEvidence(
            packageName = packageName,
            applicationLabel = applicationLabel,
            versionName = versionName,
            versionCode = versionCode,
            firstInstallTime = packageInfo.firstInstallTime,
            lastUpdateTime = packageInfo.lastUpdateTime,
            isSystemApplication =
                isSystemApplication(applicationInfo),
            isUpdatedSystemApplication =
                isUpdatedSystemApplication(applicationInfo),
            isEnabled =
                applicationInfo?.enabled ?: false
        )
    }

    /**
     * Retrieves versionCode in a way that works across Android
     * API levels.
     */
    @Suppress("DEPRECATION")
    private fun getVersionCode(
        packageInfo: PackageInfo
    ): Long {

        return if (
            android.os.Build.VERSION.SDK_INT >=
            android.os.Build.VERSION_CODES.P
        ) {

            packageInfo.longVersionCode

        } else {

            packageInfo.versionCode.toLong()
        }
    }

    /**
     * Determines whether the package is installed as a system app.
     */
    private fun isSystemApplication(
        applicationInfo: android.content.pm.ApplicationInfo?
    ): Boolean {

        if (applicationInfo == null) {
            return false
        }

        return (
            applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_SYSTEM
            ) != 0
    }

    /**
     * Determines whether the package is an updated system
     * application.
     */
    private fun isUpdatedSystemApplication(
        applicationInfo: android.content.pm.ApplicationInfo?
    ): Boolean {

        if (applicationInfo == null) {
            return false
        }

        return (
            applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
            ) != 0
    }
}

/**
 * Result of a root-package scan.
 */
data class RootPackageScanResult(

    /**
     * Packages detected during the scan.
     */
    val detectedPackages: List<RootPackageEvidence>,

    /**
     * Number of known package identifiers checked.
     */
    val packagesChecked: Int,

    /**
     * Indicates whether the scan completed normally.
     */
    val scanCompleted: Boolean,

    /**
     * Scan completion timestamp.
     */
    val scanTimestamp: Long
) {

    /**
     * True when at least one known root package was detected.
     */
    val hasDetectedPackage: Boolean
        get() = detectedPackages.isNotEmpty()

    /**
     * Number of detected root-related packages.
     */
    val detectedPackageCount: Int
        get() = detectedPackages.size

    /**
     * Returns only detected package identifiers.
     */
    val detectedPackageNames: List<String>
        get() = detectedPackages.map {
            it.packageName
        }
}

/**
 * Structured evidence representing a detected package.
 */
data class RootPackageEvidence(

    /**
     * Android package identifier.
     */
    val packageName: String,

    /**
     * Human-readable application label.
     */
    val applicationLabel: String?,

    /**
     * Installed application version.
     */
    val versionName: String?,

    /**
     * Numeric application version.
     */
    val versionCode: Long,

    /**
     * Application installation timestamp.
     */
    val firstInstallTime: Long,

    /**
     * Last application update timestamp.
     */
    val lastUpdateTime: Long,

    /**
     * Whether the application is a system application.
     */
    val isSystemApplication: Boolean,

    /**
     * Whether the application is an updated system application.
     */
    val isUpdatedSystemApplication: Boolean,

    /**
     * Whether Android currently reports the package as enabled.
     */
    val isEnabled: Boolean
)
