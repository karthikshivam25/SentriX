package com.sentrix.security.permissions

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * DangerousPermissionDetector
 *
 * Detects and analyzes Android permissions that have a
 * dangerous protection level or represent sensitive
 * capabilities from the SentriX security perspective.
 *
 * Responsibilities:
 * - Detect dangerous permissions.
 * - Determine whether dangerous permissions are declared.
 * - Determine whether dangerous permissions are granted.
 * - Detect sensitive dangerous permissions.
 * - Detect combinations of dangerous permissions.
 * - Generate dangerous-permission findings.
 * - Produce a dangerous-permission security report.
 *
 * This class does NOT:
 * - Request permissions.
 * - Revoke permissions.
 * - Modify application state.
 * - Declare an application malicious solely because it
 *   requests dangerous permissions.
 *
 * Dangerous permissions can be completely legitimate.
 * SentriX should correlate these results with:
 * - Application behavior
 * - APK analysis
 * - Malware analysis
 * - Network activity
 * - Threat intelligence
 * - Permission usage
 *
 * Architecture:
 *
 * PermissionManager
 *        ↓
 * PermissionChecker
 *        ↓
 * DangerousPermissionDetector
 *        ↓
 * PermissionAnalyzer
 *        ↓
 * PermissionRiskAnalyzer
 */
class DangerousPermissionDetector(
    private val context: Context,
    private val permissionChecker: PermissionChecker =
        PermissionChecker(context)
) {

    private val applicationContext =
        context.applicationContext

    private val packageManager =
        applicationContext.packageManager

    /**
     * Returns Android permissions from a supplied collection
     * that have a dangerous protection level.
     */
    fun detectDangerousPermissions(
        permissions: List<String>
    ): List<String> {

        return permissions.filter {
            isDangerousPermission(it)
        }
    }

    /**
     * Determines whether one permission has Android's
     * dangerous protection level.
     */
    fun isDangerousPermission(
        permission: String
    ): Boolean {

        return try {

            val permissionInfo =
                packageManager.getPermissionInfo(
                    permission,
                    0
                )

            val baseProtectionLevel =
                permissionInfo.protectionLevel and
                        PermissionInfo.PROTECTION_MASK_BASE

            baseProtectionLevel ==
                    PermissionInfo.PROTECTION_DANGEROUS

        } catch (_: PackageManager.NameNotFoundException) {

            false

        } catch (_: Exception) {

            false
        }
    }

    /**
     * Determines whether a permission belongs to the
     * SentriX high-sensitivity permission catalog.
     *
     * This is intentionally different from Android's
     * dangerous protection level.
     */
    fun isSentriXSensitivePermission(
        permission: String
    ): Boolean {

        return permission in
                SENTRIX_SENSITIVE_PERMISSIONS
    }

    /**
     * Determines whether a permission is both Android
     * dangerous and SentriX-sensitive.
     */
    fun isSensitiveDangerousPermission(
        permission: String
    ): Boolean {

        return isDangerousPermission(permission) &&
                isSentriXSensitivePermission(permission)
    }

    /**
     * Returns sensitive dangerous permissions from a list.
     */
    fun detectSensitiveDangerousPermissions(
        permissions: List<String>
    ): List<String> {

        return permissions.filter {
            isSensitiveDangerousPermission(it)
        }
    }

    /**
     * Detects dangerous permissions declared by an application.
     */
    suspend fun detectDeclaredDangerousPermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            if (!isPackageInstalled(packageName)) {
                return@withContext emptyList()
            }

            val declared =
                getRequestedPermissions(
                    packageName
                )

            detectDangerousPermissions(
                declared
            )
        }

    /**
     * Detects dangerous permissions that are currently
     * granted to an application.
     */
    suspend fun detectGrantedDangerousPermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            val dangerous =
                detectDeclaredDangerousPermissions(
                    packageName
                )

            dangerous.filter {
                permissionChecker.isPermissionGranted(
                    packageName,
                    it
                )
            }
        }

    /**
     * Detects dangerous permissions that are declared but
     * currently denied.
     */
    suspend fun detectDeniedDangerousPermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            val dangerous =
                detectDeclaredDangerousPermissions(
                    packageName
                )

            dangerous.filter {
                permissionChecker.isPermissionDenied(
                    packageName,
                    it
                )
            }
        }

    /**
     * Detects granted dangerous permissions that are
     * considered highly sensitive by SentriX.
     */
    suspend fun detectGrantedSensitiveDangerousPermissions(
        packageName: String
    ): List<String> =
        withContext(Dispatchers.IO) {

            detectGrantedDangerousPermissions(
                packageName
            ).filter {
                isSentriXSensitivePermission(it)
            }
        }

    /**
     * Performs a complete dangerous-permission analysis.
     */
    suspend fun analyze(
        packageName: String
    ): DangerousPermissionReport =
        withContext(Dispatchers.IO) {

            if (!isPackageInstalled(packageName)) {

                return@withContext DangerousPermissionReport(
                    packageName = packageName,
                    status =
                        DangerousPermissionAnalysisStatus
                            .PACKAGE_NOT_FOUND,
                    declaredDangerousPermissions =
                        emptyList(),
                    grantedDangerousPermissions =
                        emptyList(),
                    deniedDangerousPermissions =
                        emptyList(),
                    sensitiveDangerousPermissions =
                        emptyList(),
                    findings = emptyList(),
                    riskLevel =
                        PermissionRiskLevel.LOW
                )
            }

            val declared =
                detectDeclaredDangerousPermissions(
                    packageName
                )

            val granted =
                declared.filter {
                    permissionChecker.isPermissionGranted(
                        packageName,
                        it
                    )
                }

            val denied =
                declared.filterNot {
                    it in granted
                }

            val sensitive =
                granted.filter {
                    isSentriXSensitivePermission(it)
                }

            val findings =
                detectFindings(
                    packageName = packageName,
                    declared = declared,
                    granted = granted,
                    sensitive = sensitive
                )

            val riskLevel =
                determineDangerousPermissionRisk(
                    granted = granted,
                    sensitive = sensitive,
                    findings = findings
                )

            DangerousPermissionReport(
                packageName = packageName,
                status =
                    DangerousPermissionAnalysisStatus
                        .COMPLETED,
                declaredDangerousPermissions =
                    declared,
                grantedDangerousPermissions =
                    granted,
                deniedDangerousPermissions =
                    denied,
                sensitiveDangerousPermissions =
                    sensitive,
                findings = findings,
                riskLevel = riskLevel
            )
        }

    /**
     * Detects combinations of dangerous permissions that
     * warrant additional investigation.
     *
     * These are security indicators, not malware verdicts.
     */
    fun detectDangerousPermissionCombinations(
        permissions: List<String>
    ): List<DangerousPermissionCombination> {

        val granted =
            permissions.toSet()

        val combinations =
            mutableListOf<DangerousPermissionCombination>()

        /*
         * SMS + Contacts
         */
        if (
            granted.contains(
                Manifest.permission.READ_SMS
            ) &&
            granted.contains(
                Manifest.permission.READ_CONTACTS
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "SMS_CONTACTS",
                    title =
                        "SMS and Contacts Access",
                    description =
                        "The application can access both SMS " +
                        "messages and contact data.",
                    severity =
                        PermissionFindingSeverity.HIGH,
                    permissions = listOf(
                        Manifest.permission.READ_SMS,
                        Manifest.permission.READ_CONTACTS
                    )
                )
        }

        /*
         * SMS + Phone
         */
        if (
            (
                granted.contains(
                    Manifest.permission.READ_SMS
                ) ||
                granted.contains(
                    Manifest.permission.RECEIVE_SMS
                )
            ) &&
            granted.contains(
                Manifest.permission.CALL_PHONE
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "SMS_PHONE",
                    title =
                        "SMS and Phone Access",
                    description =
                        "The application can access SMS and " +
                        "phone-call functionality.",
                    severity =
                        PermissionFindingSeverity.HIGH,
                    permissions = listOf(
                        Manifest.permission.READ_SMS,
                        Manifest.permission.CALL_PHONE
                    )
                )
        }

        /*
         * Contacts + Location
         */
        if (
            granted.contains(
                Manifest.permission.READ_CONTACTS
            ) &&
            (
                granted.contains(
                    Manifest.permission.ACCESS_FINE_LOCATION
                ) ||
                granted.contains(
                    Manifest.permission.ACCESS_COARSE_LOCATION
                )
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "CONTACTS_LOCATION",
                    title =
                        "Contacts and Location Access",
                    description =
                        "The application can access both " +
                        "contact information and device location.",
                    severity =
                        PermissionFindingSeverity.MEDIUM,
                    permissions = listOf(
                        Manifest.permission.READ_CONTACTS,
                        Manifest.permission.ACCESS_FINE_LOCATION
                    )
                )
        }

        /*
         * Camera + Microphone
         */
        if (
            granted.contains(
                Manifest.permission.CAMERA
            ) &&
            granted.contains(
                Manifest.permission.RECORD_AUDIO
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "CAMERA_MICROPHONE",
                    title =
                        "Camera and Microphone Access",
                    description =
                        "The application has access to both " +
                        "camera and microphone capabilities.",
                    severity =
                        PermissionFindingSeverity.MEDIUM,
                    permissions = listOf(
                        Manifest.permission.CAMERA,
                        Manifest.permission.RECORD_AUDIO
                    )
                )
        }

        /*
         * Camera + Location + Microphone
         */
        if (
            granted.contains(
                Manifest.permission.CAMERA
            ) &&
            granted.contains(
                Manifest.permission.RECORD_AUDIO
            ) &&
            granted.contains(
                Manifest.permission.ACCESS_FINE_LOCATION
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "CAMERA_MICROPHONE_LOCATION",
                    title =
                        "Broad Sensor and Location Access",
                    description =
                        "The application has simultaneous access " +
                        "to camera, microphone and precise location.",
                    severity =
                        PermissionFindingSeverity.HIGH,
                    permissions = listOf(
                        Manifest.permission.CAMERA,
                        Manifest.permission.RECORD_AUDIO,
                        Manifest.permission.ACCESS_FINE_LOCATION
                    )
                )
        }

        /*
         * Call Log + Contacts
         */
        if (
            granted.contains(
                Manifest.permission.READ_CALL_LOG
            ) &&
            granted.contains(
                Manifest.permission.READ_CONTACTS
            )
        ) {

            combinations +=
                DangerousPermissionCombination(
                    id = "CALL_LOG_CONTACTS",
                    title =
                        "Call Log and Contacts Access",
                    description =
                        "The application can access call history " +
                        "and contact information.",
                    severity =
                        PermissionFindingSeverity.HIGH,
                    permissions = listOf(
                        Manifest.permission.READ_CALL_LOG,
                        Manifest.permission.READ_CONTACTS
                    )
                )
        }

        /*
         * Broad communication access.
         */
        val communicationCount =
            granted.count {
                it in COMMUNICATION_PERMISSIONS
            }

        if (communicationCount >= 4) {

            combinations +=
                DangerousPermissionCombination(
                    id = "BROAD_COMMUNICATION_ACCESS",
                    title =
                        "Broad Communication Access",
                    description =
                        "The application has several SMS, call " +
                        "or phone-related dangerous permissions.",
                    severity =
                        PermissionFindingSeverity.HIGH,
                    permissions =
                        granted.filter {
                            it in COMMUNICATION_PERMISSIONS
                        }
                )
        }

        return combinations
    }

    /**
     * Builds security findings from the detected
     * dangerous permission state.
     */
    private fun detectFindings(
        packageName: String,
        declared: List<String>,
        granted: List<String>,
        sensitive: List<String>
    ): List<DangerousPermissionFinding> {

        val findings =
            mutableListOf<DangerousPermissionFinding>()

        /*
         * Large dangerous-permission footprint.
         */
        if (granted.size >= 10) {

            findings += DangerousPermissionFinding(
                id = "LARGE_DANGEROUS_PERMISSION_SET",
                title =
                    "Large Dangerous Permission Set",
                description =
                    "The application currently has " +
                    "${granted.size} dangerous permissions granted.",
                severity =
                    if (granted.size >= 15) {
                        PermissionFindingSeverity.HIGH
                    } else {
                        PermissionFindingSeverity.MEDIUM
                    },
                permissions = granted
            )
        }

        /*
         * Sensitive dangerous permissions.
         */
        if (sensitive.isNotEmpty()) {

            findings += DangerousPermissionFinding(
                id = "SENSITIVE_DANGEROUS_PERMISSIONS",
                title =
                    "Sensitive Dangerous Permissions",
                description =
                    "The application has ${sensitive.size} " +
                    "dangerous permission(s) that expose " +
                    "particularly sensitive capabilities or data.",
                severity =
                    when {
                        sensitive.size >= 6 ->
                            PermissionFindingSeverity.HIGH

                        sensitive.size >= 3 ->
                            PermissionFindingSeverity.MEDIUM

                        else ->
                            PermissionFindingSeverity.LOW
                    },
                permissions = sensitive
            )
        }

        /*
         * Suspicious combinations.
         */
        detectDangerousPermissionCombinations(
            granted
        ).forEach { combination ->

            findings += DangerousPermissionFinding(
                id =
                    "COMBINATION_${combination.id}",
                title =
                    combination.title,
                description =
                    combination.description,
                severity =
                    combination.severity,
                permissions =
                    combination.permissions
            )
        }

        /*
         * SMS access.
         */
        val smsPermissions =
            granted.filter {
                it in SMS_PERMISSIONS
            }

        if (smsPermissions.isNotEmpty()) {

            findings += DangerousPermissionFinding(
                id = "SMS_ACCESS",
                title =
                    "SMS Access",
                description =
                    "The application has access to SMS-related " +
                    "functionality. This can expose sensitive " +
                    "messages and potentially OTP-related data.",
                severity =
                    PermissionFindingSeverity.HIGH,
                permissions =
                    smsPermissions
            )
        }

        /*
         * Call log access.
         */
        val callLogPermissions =
            granted.filter {
                it in CALL_LOG_PERMISSIONS
            }

        if (callLogPermissions.isNotEmpty()) {

            findings += DangerousPermissionFinding(
                id = "CALL_LOG_ACCESS",
                title =
                    "Call Log Access",
                description =
                    "The application can access call history " +
                    "information.",
                severity =
                    PermissionFindingSeverity.HIGH,
                permissions =
                    callLogPermissions
            )
        }

        return findings.distinctBy {
            it.id
        }
    }

    /**
     * Calculates a lightweight dangerous-permission risk level.
     *
     * The final SentriX risk score should be calculated by
     * PermissionRiskAnalyzer after correlation with other
     * security signals.
     */
    private fun determineDangerousPermissionRisk(
        granted: List<String>,
        sensitive: List<String>,
        findings: List<DangerousPermissionFinding>
    ): PermissionRiskLevel {

        var score = 0

        score += minOf(
            granted.size * 3,
            30
        )

        score += minOf(
            sensitive.size * 6,
            30
        )

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
     * Checks whether a package is installed.
     */
    private fun isPackageInstalled(
        packageName: String
    ): Boolean {

        return try {

            packageManager.getApplicationInfo(
                packageName,
                0
            )

            true

        } catch (_: PackageManager.NameNotFoundException) {

            false
        }
    }

    /**
     * Retrieves permissions requested by an application.
     */
    @Suppress("DEPRECATION")
    private fun getRequestedPermissions(
        packageName: String
    ): List<String> {

        return try {

            val packageInfo =
                if (
                    Build.VERSION.SDK_INT >=
                    Build.VERSION_CODES.TIRAMISU
                ) {

                    packageManager.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(
                            PackageManager.GET_PERMISSIONS
                                .toLong()
                        )
                    )

                } else {

                    packageManager.getPackageInfo(
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

    companion object {

        /**
         * Permissions treated as particularly sensitive
         * by SentriX.
         */
        val SENTRIX_SENSITIVE_PERMISSIONS =
            setOf(

                // SMS
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,

                // Contacts
                Manifest.permission.READ_CONTACTS,
                Manifest.permission.WRITE_CONTACTS,

                // Calls
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.CALL_PHONE,
                Manifest.permission.ANSWER_PHONE_CALLS,

                // Location
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,

                // Sensors
                Manifest.permission.CAMERA,
                Manifest.permission.RECORD_AUDIO,

                // Phone state
                Manifest.permission.READ_PHONE_STATE,

                // Calendar
                Manifest.permission.READ_CALENDAR,
                Manifest.permission.WRITE_CALENDAR
            )

        /**
         * SMS-related permissions.
         */
        val SMS_PERMISSIONS =
            setOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS
            )

        /**
         * Call-log-related permissions.
         */
        val CALL_LOG_PERMISSIONS =
            setOf(
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG
            )

        /**
         * Communication-related permissions.
         */
        val COMMUNICATION_PERMISSIONS =
            setOf(
                Manifest.permission.READ_SMS,
                Manifest.permission.RECEIVE_SMS,
                Manifest.permission.SEND_SMS,
                Manifest.permission.READ_CALL_LOG,
                Manifest.permission.WRITE_CALL_LOG,
                Manifest.permission.CALL_PHONE,
                Manifest.permission.ANSWER_PHONE_CALLS
            )
    }
}

/**
 * Result of dangerous-permission analysis.
 */
data class DangerousPermissionReport(

    val packageName: String,

    val status: DangerousPermissionAnalysisStatus,

    val declaredDangerousPermissions: List<String>,

    val grantedDangerousPermissions: List<String>,

    val deniedDangerousPermissions: List<String>,

    val sensitiveDangerousPermissions: List<String>,

    val findings: List<DangerousPermissionFinding>,

    val riskLevel: PermissionRiskLevel
) {

    /**
     * Indicates whether the application declares
     * any dangerous permissions.
     */
    val hasDangerousPermissions: Boolean
        get() =
            declaredDangerousPermissions.isNotEmpty()

    /**
     * Indicates whether dangerous permissions are
     * currently granted.
     */
    val hasGrantedDangerousPermissions: Boolean
        get() =
            grantedDangerousPermissions.isNotEmpty()

    /**
     * Indicates whether sensitive dangerous permissions
     * are currently granted.
     */
    val hasSensitiveDangerousPermissions: Boolean
        get() =
            sensitiveDangerousPermissions.isNotEmpty()

    /**
     * Number of dangerous permissions currently granted.
     */
    val grantedCount: Int
        get() =
            grantedDangerousPermissions.size
}

/**
 * Dangerous-permission analysis status.
 */
enum class DangerousPermissionAnalysisStatus {

    COMPLETED,

    PACKAGE_NOT_FOUND
}

/**
 * Dangerous-permission finding.
 */
data class DangerousPermissionFinding(

    val id: String,

    val title: String,

    val description: String,

    val severity: PermissionFindingSeverity,

    val permissions: List<String>
)

/**
 * Represents a potentially significant combination
 * of dangerous permissions.
 */
data class DangerousPermissionCombination(

    val id: String,

    val title: String,

    val description: String,

    val severity: PermissionFindingSeverity,

    val permissions: List<String>
)
