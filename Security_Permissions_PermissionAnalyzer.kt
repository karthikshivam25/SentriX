package com.sentrix.security.permissions

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PermissionAnalyzer
 *
 * Performs higher-level security analysis of Android application
 * permissions.
 *
 * Responsibilities:
 * - Analyze an application's complete permission footprint.
 * - Identify sensitive permission combinations.
 * - Detect excessive permission usage.
 * - Detect suspicious permission patterns.
 * - Identify permissions associated with common attack surfaces.
 * - Generate security findings.
 * - Produce an overall permission-analysis result.
 *
 * This class does NOT request permissions.
 * It analyzes permissions already declared/granted by applications.
 *
 * Architecture:
 *
 * PermissionManager
 *        ↓
 * PermissionChecker
 *        ↓
 * PermissionAnalyzer
 *        ↓
 * PermissionRiskEvaluator
 *        ↓
 * Threat / Security Reporting
 */
class PermissionAnalyzer(
    private val context: Context,
    private val permissionChecker: PermissionChecker =
        PermissionChecker(context)
) {

    private val applicationContext =
        context.applicationContext

    /**
     * Performs a complete permission analysis.
     *
     * @param packageName Android package being analyzed.
     *
     * @return PermissionAnalysisReport containing findings,
     *         risk score and permission statistics.
     */
    suspend fun analyze(
        packageName: String
    ): PermissionAnalysisReport =
        withContext(Dispatchers.IO) {

            if (!isPackageAvailable(packageName)) {

                return@withContext PermissionAnalysisReport(
                    packageName = packageName,
                    applicationName = null,
                    status = PermissionAnalysisStatus.PACKAGE_NOT_FOUND,
                    riskLevel = PermissionRiskLevel.LOW,
                    riskScore = 0,
                    totalPermissions = 0,
                    grantedPermissions = 0,
                    deniedPermissions = 0,
                    dangerousPermissions = 0,
                    grantedDangerousPermissions = 0,
                    sensitivePermissions = 0,
                    findings = emptyList()
                )
            }

            val permissions =
                getRequestedPermissions(packageName)

            val checkResults =
                permissionChecker.checkPermissionSet(
                    packageName = packageName,
                    permissions = permissions
                )

            val findings =
                mutableListOf<PermissionFinding>()

            findings += detectExcessivePermissions(
                checkResults
            )

            findings += detectSensitivePermissions(
                checkResults
            )

            findings += detectCommunicationAccess(
                checkResults
            )

            findings += detectLocationAccess(
                checkResults
            )

            findings += detectSensorAccess(
                checkResults
            )

            findings += detectContactAccess(
                checkResults
            )

            findings += detectStorageAccess(
                checkResults
            )

            findings += detectSuspiciousPermissionCombinations(
                checkResults
            )

            findings += detectBroadGrantedPermissions(
                checkResults
            )

            val uniqueFindings =
                findings.distinctBy {
                    it.id
                }

            val riskScore =
                calculateRiskScore(
                    checkResults = checkResults,
                    findings = uniqueFindings
                )

            val riskLevel =
                determineRiskLevel(riskScore)

            PermissionAnalysisReport(
                packageName = packageName,
                applicationName =
                    getApplicationLabel(packageName),
                status = PermissionAnalysisStatus.COMPLETED,
                riskLevel = riskLevel,
                riskScore = riskScore,
                totalPermissions = checkResults.size,
                grantedPermissions =
                    checkResults.count { it.granted },
                deniedPermissions =
                    checkResults.count {
                        it.declared && !it.granted
                    },
                dangerousPermissions =
                    checkResults.count {
                        it.dangerous
                    },
                grantedDangerousPermissions =
                    checkResults.count {
                        it.dangerous && it.granted
                    },
                sensitivePermissions =
                    checkResults.count {
                        it.sensitive
                    },
                findings = uniqueFindings
            )
        }

    /**
     * Analyzes only permissions supplied by the caller.
     *
     * Useful when another SentriX subsystem has already
     * extracted permissions from an APK.
     */
    suspend fun analyzePermissions(
        packageName: String,
        permissions: List<String>
    ): PermissionAnalysisReport =
        withContext(Dispatchers.IO) {

            val results =
                permissionChecker.checkPermissionSet(
                    packageName,
                    permissions
                )

            val findings =
                mutableListOf<PermissionFinding>()

            findings += detectExcessivePermissions(results)
            findings += detectSensitivePermissions(results)
            findings += detectCommunicationAccess(results)
            findings += detectLocationAccess(results)
            findings += detectSensorAccess(results)
            findings += detectContactAccess(results)
            findings += detectStorageAccess(results)
            findings += detectSuspiciousPermissionCombinations(results)
            findings += detectBroadGrantedPermissions(results)

            val uniqueFindings =
                findings.distinctBy { it.id }

            val riskScore =
                calculateRiskScore(
                    results,
                    uniqueFindings
                )

            PermissionAnalysisReport(
                packageName = packageName,
                applicationName =
                    getApplicationLabel(packageName),
                status = PermissionAnalysisStatus.COMPLETED,
                riskLevel =
                    determineRiskLevel(riskScore),
                riskScore = riskScore,
                totalPermissions = results.size,
                grantedPermissions =
                    results.count { it.granted },
                deniedPermissions =
                    results.count {
                        it.declared && !it.granted
                    },
                dangerousPermissions =
                    results.count { it.dangerous },
                grantedDangerousPermissions =
                    results.count {
                        it.dangerous && it.granted
                    },
                sensitivePermissions =
                    results.count { it.sensitive },
                findings = uniqueFindings
            )
        }

    /**
     * Detects applications requesting an unusually large
     * number of permissions.
     *
     * Permission quantity alone does not prove malicious behavior.
     */
    private fun detectExcessivePermissions(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        if (results.size < 15) {
            return emptyList()
        }

        return listOf(
            PermissionFinding(
                id = "EXCESSIVE_PERMISSION_COUNT",
                title = "Excessive Permission Footprint",
                description =
                    "The application requests ${results.size} " +
                    "permissions, which creates a comparatively " +
                    "large security and privacy attack surface.",
                severity =
                    if (results.size >= 25) {
                        PermissionFindingSeverity.HIGH
                    } else {
                        PermissionFindingSeverity.MEDIUM
                    },
                category =
                    PermissionFindingCategory.PERMISSION_SURFACE,
                permissions =
                    results.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects granted sensitive permissions.
     */
    private fun detectSensitivePermissions(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val grantedSensitive =
            results.filter {
                it.sensitive && it.granted
            }

        if (grantedSensitive.isEmpty()) {
            return emptyList()
        }

        val severity =
            when {
                grantedSensitive.size >= 5 ->
                    PermissionFindingSeverity.HIGH

                grantedSensitive.size >= 3 ->
                    PermissionFindingSeverity.MEDIUM

                else ->
                    PermissionFindingSeverity.LOW
            }

        return listOf(
            PermissionFinding(
                id = "GRANTED_SENSITIVE_PERMISSIONS",
                title = "Sensitive Permissions Granted",
                description =
                    "The application has access to " +
                    "${grantedSensitive.size} sensitive permission(s). " +
                    "These permissions should be reviewed against " +
                    "the application's expected functionality.",
                severity = severity,
                category =
                    PermissionFindingCategory.SENSITIVE_ACCESS,
                permissions =
                    grantedSensitive.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects SMS/call-related access.
     *
     * This category is particularly important for SentriX because
     * SMS and call permissions can expose OTPs, messages and
     * communication metadata.
     */
    private fun detectCommunicationAccess(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val communicationPermissions =
            setOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.CALL_PHONE
            )

        val matches =
            results.filter {
                it.granted &&
                        it.permission in communicationPermissions
            }

        if (matches.isEmpty()) {
            return emptyList()
        }

        return listOf(
            PermissionFinding(
                id = "COMMUNICATION_ACCESS",
                title = "Communication Access Granted",
                description =
                    "The application has access to SMS or " +
                    "call-related functionality.",
                severity =
                    PermissionFindingSeverity.HIGH,
                category =
                    PermissionFindingCategory.COMMUNICATION_ACCESS,
                permissions =
                    matches.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects location access.
     */
    private fun detectLocationAccess(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val locationPermissions =
            setOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            )

        val matches =
            results.filter {
                it.granted &&
                        it.permission in locationPermissions
            }

        if (matches.isEmpty()) {
            return emptyList()
        }

        val hasFineLocation =
            matches.any {
                it.permission ==
                        Manifest.permission.ACCESS_FINE_LOCATION
            }

        return listOf(
            PermissionFinding(
                id = "LOCATION_ACCESS",
                title = "Location Access Granted",
                description =
                    if (hasFineLocation) {
                        "The application has access to precise " +
                        "device location."
                    } else {
                        "The application has access to approximate " +
                        "device location."
                    },
                severity =
                    if (hasFineLocation) {
                        PermissionFindingSeverity.MEDIUM
                    } else {
                        PermissionFindingSeverity.LOW
                    },
                category =
                    PermissionFindingCategory.LOCATION_ACCESS,
                permissions =
                    matches.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects camera and microphone access.
     */
    private fun detectSensorAccess(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val sensorPermissions =
            setOf(
                Manifest.permission.CAMERA,
                Manifest.permission.RECORD_AUDIO
            )

        val matches =
            results.filter {
                it.granted &&
                        it.permission in sensorPermissions
            }

        if (matches.isEmpty()) {
            return emptyList()
        }

        val hasCamera =
            matches.any {
                it.permission ==
                        Manifest.permission.CAMERA
            }

        val hasMicrophone =
            matches.any {
                it.permission ==
                        Manifest.permission.RECORD_AUDIO
            }

        val description =
            when {
                hasCamera && hasMicrophone ->
                    "The application has access to both camera " +
                    "and microphone functionality."

                hasCamera ->
                    "The application has access to the device camera."

                else ->
                    "The application has access to the device microphone."
            }

        return listOf(
            PermissionFinding(
                id = "SENSOR_ACCESS",
                title = "Camera or Microphone Access",
                description = description,
                severity =
                    PermissionFindingSeverity.MEDIUM,
                category =
                    PermissionFindingCategory.SENSOR_ACCESS,
                permissions =
                    matches.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects contacts access.
     */
    private fun detectContactAccess(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val contactPermissions =
            setOf(
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.WRITE_CONTACTS
            )

        val matches =
            results.filter {
                it.granted &&
                        it.permission in contactPermissions
            }

        if (matches.isEmpty()) {
            return emptyList()
        }

        return listOf(
            PermissionFinding(
                id = "CONTACT_ACCESS",
                title = "Contact Data Access",
                description =
                    "The application has access to device " +
                    "contact information.",
                severity =
                    PermissionFindingSeverity.MEDIUM,
                category =
                    PermissionFindingCategory.PERSONAL_DATA,
                permissions =
                    matches.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects storage-related access.
     *
     * Storage permissions behave differently across Android
     * versions, therefore this finding should be interpreted
     * together with the device API level.
     */
    private fun detectStorageAccess(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val storagePermissions =
            setOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            )

        val matches =
            results.filter {
                it.granted &&
                        it.permission in storagePermissions
            }

        if (matches.isEmpty()) {
            return emptyList()
        }

        return listOf(
            PermissionFinding(
                id = "STORAGE_ACCESS",
                title = "External Storage Access",
                description =
                    "The application has permission to access " +
                    "external storage resources.",
                severity =
                    PermissionFindingSeverity.MEDIUM,
                category =
                    PermissionFindingCategory.FILE_ACCESS,
                permissions =
                    matches.map {
                        it.permission
                    }
            )
        )
    }

    /**
     * Detects combinations that can represent a higher-risk
     * capability set.
     *
     * Important:
     * A combination is an indicator for further investigation,
     * not proof that an application is malicious.
     */
    private fun detectSuspiciousPermissionCombinations(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val granted =
            results
                .filter { it.granted }
                .map { it.permission }
                .toSet()

        val findings =
            mutableListOf<PermissionFinding>()

        /*
         * SMS + Contacts
         *
         * Potentially exposes communications and contact data.
         */
        if (
            granted.contains(
                Manifest.permission.READ_SMS
            ) &&
            granted.contains(
                Manifest.permission.READ_CONTACTS
            )
        ) {

            findings += PermissionFinding(
                id = "SMS_CONTACT_COMBINATION",
                title = "SMS and Contact Access Combination",
                description =
                    "The application can access both SMS and " +
                    "contact data. This combination warrants " +
                    "additional behavioral analysis.",
                severity =
                    PermissionFindingSeverity.HIGH,
                category =
                    PermissionFindingCategory.SUSPICIOUS_COMBINATION,
                permissions = listOf(
                    Manifest.permission.READ_SMS,
                    Manifest.permission.READ_CONTACTS
                )
            )
        }

        /*
         * Location + microphone + camera
         *
         * Broad sensor/location access.
         */
        if (
            granted.contains(
                Manifest.permission.ACCESS_FINE_LOCATION
            ) &&
            granted.contains(
                Manifest.permission.RECORD_AUDIO
            ) &&
            granted.contains(
                Manifest.permission.CAMERA
            )
        ) {

            findings += PermissionFinding(
                id = "LOCATION_SENSOR_COMBINATION",
                title = "Broad Sensor and Location Access",
                description =
                    "The application has simultaneous access to " +
                    "precise location, microphone and camera.",
                severity =
                    PermissionFindingSeverity.HIGH,
                category =
                    PermissionFindingCategory.SUSPICIOUS_COMBINATION,
                permissions = listOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.RECORD_AUDIO,
                    Manifest.permission.CAMERA
                )
            )
        }

        /*
         * SMS + phone + contacts
         *
         * Broad communication and identity-related access.
         */
        if (
            granted.contains(
                Manifest.permission.READ_SMS
            ) &&
            granted.contains(
                Manifest.permission.CALL_PHONE
            ) &&
            granted.contains(
                Manifest.permission.READ_CONTACTS
            )
        ) {

            findings += PermissionFinding(
                id = "COMMUNICATION_IDENTITY_COMBINATION",
                title = "Broad Communication Access",
                description =
                    "The application has simultaneous access to " +
                    "SMS, phone functionality and contacts.",
                severity =
                    PermissionFindingSeverity.HIGH,
                category =
                    PermissionFindingCategory.SUSPICIOUS_COMBINATION,
                permissions = listOf(
                    Manifest.permission.READ_SMS,
                    Manifest.permission.CALL_PHONE,
                    Manifest.permission.READ_CONTACTS
                )
            )
        }

        return findings
    }

    /**
     * Detects a large number of dangerous permissions
     * being granted simultaneously.
     */
    private fun detectBroadGrantedPermissions(
        results: List<PermissionCheckResult>
    ): List<PermissionFinding> {

        val grantedDangerous =
            results.count {
                it.dangerous && it.granted
            }

        if (grantedDangerous < 8) {
            return emptyList()
        }

        return listOf(
            PermissionFinding(
                id = "BROAD_DANGEROUS_ACCESS",
                title = "Broad Dangerous Permission Access",
                description =
                    "The application currently has " +
                    "$grantedDangerous dangerous permissions granted. " +
                    "Its permission footprint should be reviewed " +
                    "against its declared functionality.",
                severity =
                    if (grantedDangerous >= 12) {
                        PermissionFindingSeverity.HIGH
                    } else {
                        PermissionFindingSeverity.MEDIUM
                    },
                category =
                    PermissionFindingCategory.PERMISSION_SURFACE,
                permissions =
                    results
                        .filter {
                            it.dangerous && it.granted
                        }
                        .map {
                            it.permission
                        }
            )
        )
    }

    /**
     * Calculates an overall heuristic risk score.
     *
     * Score range:
     * 0 - 100
     */
    private fun calculateRiskScore(
        checkResults: List<PermissionCheckResult>,
        findings: List<PermissionFinding>
    ): Int {

        var score = 0

        val grantedDangerous =
            checkResults.count {
                it.dangerous && it.granted
            }

        val grantedSensitive =
            checkResults.count {
                it.sensitive && it.granted
            }

        /*
         * Base permission footprint.
         */
        score += when {
            checkResults.size >= 25 -> 20
            checkResults.size >= 15 -> 12
            checkResults.size >= 10 -> 6
            else -> 0
        }

        /*
         * Dangerous permissions.
         */
        score += minOf(
            grantedDangerous * 3,
            25
        )

        /*
         * Sensitive permissions.
         */
        score += minOf(
            grantedSensitive * 5,
            30
        )

        /*
         * Finding severity.
         */
        findings.forEach { finding ->

            score += when (
                finding.severity
            ) {

                PermissionFindingSeverity.LOW ->
                    3

                PermissionFindingSeverity.MEDIUM ->
                    7

                PermissionFindingSeverity.HIGH ->
                    12

                PermissionFindingSeverity.CRITICAL ->
                    20
            }
        }

        return score.coerceIn(
            0,
            100
        )
    }

    /**
     * Maps numerical risk score to a risk level.
     */
    private fun determineRiskLevel(
        score: Int
    ): PermissionRiskLevel {

        return when {

            score >= 75 ->
                PermissionRiskLevel.CRITICAL

            score >= 50 ->
                PermissionRiskLevel.HIGH

            score >= 25 ->
                PermissionRiskLevel.MEDIUM

            else ->
                PermissionRiskLevel.LOW
        }
    }

    /**
     * Checks whether an application is installed.
     */
    private fun isPackageAvailable(
        packageName: String
    ): Boolean {

        return permissionChecker
            .isPackageAvailable(packageName)
    }

    /**
     * Retrieves the application label.
     */
    private fun getApplicationLabel(
        packageName: String
    ): String? {

        return try {

            val applicationInfo =
                applicationContext
                    .packageManager
                    .getApplicationInfo(
                        packageName,
                        0
                    )

            applicationContext
                .packageManager
                .getApplicationLabel(
                    applicationInfo
                )
                .toString()

        } catch (_: Exception) {

            null
        }
    }

    /**
     * Retrieves requested permissions.
     */
    @Suppress("DEPRECATION")
    private fun getRequestedPermissions(
        packageName: String
    ): List<String> {

        return try {

            val packageInfo =
                if (
                    android.os.Build.VERSION.SDK_INT >=
                    android.os.Build.VERSION_CODES.TIRAMISU
                ) {

                    applicationContext
                        .packageManager
                        .getPackageInfo(
                            packageName,
                            PackageManager.PackageInfoFlags.of(
                                PackageManager.GET_PERMISSIONS
                                    .toLong()
                            )
                        )

                } else {

                    applicationContext
                        .packageManager
                        .getPackageInfo(
                            packageName,
                            PackageManager.GET_PERMISSIONS
                        )
                }

            packageInfo.requestedPermissions
                ?.toList()
                ?: emptyList()

        } catch (_: Exception) {

            emptyList()
        }
    }
}

/**
 * Complete result produced by PermissionAnalyzer.
 */
data class PermissionAnalysisReport(

    val packageName: String,

    val applicationName: String?,

    val status: PermissionAnalysisStatus,

    val riskLevel: PermissionRiskLevel,

    val riskScore: Int,

    val totalPermissions: Int,

    val grantedPermissions: Int,

    val deniedPermissions: Int,

    val dangerousPermissions: Int,

    val grantedDangerousPermissions: Int,

    val sensitivePermissions: Int,

    val findings: List<PermissionFinding>
) {

    /**
     * Indicates whether the analysis discovered
     * security findings.
     */
    val hasFindings: Boolean
        get() = findings.isNotEmpty()

    /**
     * Number of high/critical findings.
     */
    val highRiskFindingCount: Int
        get() = findings.count {
            it.severity == PermissionFindingSeverity.HIGH ||
                    it.severity == PermissionFindingSeverity.CRITICAL
        }

    /**
     * Indicates whether further security investigation
     * is recommended.
     */
    val requiresFurtherAnalysis: Boolean
        get() =
            riskLevel == PermissionRiskLevel.HIGH ||
                    riskLevel == PermissionRiskLevel.CRITICAL ||
                    highRiskFindingCount > 0
}

/**
 * Permission analysis execution status.
 */
enum class PermissionAnalysisStatus {

    COMPLETED,

    PACKAGE_NOT_FOUND
}

/**
 * Individual permission security finding.
 */
data class PermissionFinding(

    val id: String,

    val title: String,

    val description: String,

    val severity: PermissionFindingSeverity,

    val category: PermissionFindingCategory,

    val permissions: List<String>
)

/**
 * Finding severity.
 */
enum class PermissionFindingSeverity {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}

/**
 * Permission finding categories.
 */
enum class PermissionFindingCategory {

    PERMISSION_SURFACE,

    SENSITIVE_ACCESS,

    COMMUNICATION_ACCESS,

    LOCATION_ACCESS,

    SENSOR_ACCESS,

    PERSONAL_DATA,

    FILE_ACCESS,

    SUSPICIOUS_COMBINATION
}
