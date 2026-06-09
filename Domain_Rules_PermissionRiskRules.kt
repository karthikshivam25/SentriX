package com.sentrix.domain.rules

/**
 * SentriX Permission Risk Rules
 *
 * Evaluates application permissions and calculates
 * permission-based security risk scores.
 */
object PermissionRiskRules {

    enum class RiskLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private val CRITICAL_PERMISSIONS = setOf(
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    private val HIGH_RISK_PERMISSIONS = setOf(
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE"
    )

    private val MEDIUM_RISK_PERMISSIONS = setOf(
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.NFC",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE"
    )

    /**
     * Calculate risk score from permission list.
     */
    fun calculateRiskScore(permissions: List<String>): Int {

        var score = 0

        permissions.forEach { permission ->

            score += when {
                CRITICAL_PERMISSIONS.contains(permission) -> 15
                HIGH_RISK_PERMISSIONS.contains(permission) -> 8
                MEDIUM_RISK_PERMISSIONS.contains(permission) -> 3
                else -> 1
            }
        }

        return score.coerceAtMost(100)
    }

    /**
     * Determine overall risk level.
     */
    fun determineRiskLevel(score: Int): RiskLevel {
        return when {
            score >= 75 -> RiskLevel.CRITICAL
            score >= 50 -> RiskLevel.HIGH
            score >= 25 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }

    /**
     * Check if application contains dangerous permissions.
     */
    fun hasDangerousPermissions(
        permissions: List<String>
    ): Boolean {
        return permissions.any {
            CRITICAL_PERMISSIONS.contains(it)
        }
    }

    /**
     * Count critical permissions.
     */
    fun countCriticalPermissions(
        permissions: List<String>
    ): Int {
        return permissions.count {
            CRITICAL_PERMISSIONS.contains(it)
        }
    }

    /**
     * Count high-risk permissions.
     */
    fun countHighRiskPermissions(
        permissions: List<String>
    ): Int {
        return permissions.count {
            HIGH_RISK_PERMISSIONS.contains(it)
        }
    }

    /**
     * Check if permission combination is suspicious.
     */
    fun isSuspiciousCombination(
        permissions: List<String>
    ): Boolean {

        val hasSmsAccess =
            permissions.any {
                it.contains("SMS")
            }

        val hasAccessibilityAccess =
            permissions.contains(
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            )

        val hasOverlayPermission =
            permissions.contains(
                "android.permission.SYSTEM_ALERT_WINDOW"
            )

        val hasContactAccess =
            permissions.contains(
                "android.permission.READ_CONTACTS"
            )

        return (hasSmsAccess && hasAccessibilityAccess) ||
                (hasOverlayPermission && hasAccessibilityAccess) ||
                (hasSmsAccess && hasContactAccess)
    }

    /**
     * Generate risk summary.
     */
    fun getRiskSummary(
        permissions: List<String>
    ): String {

        val score = calculateRiskScore(permissions)
        val riskLevel = determineRiskLevel(score)

        return when (riskLevel) {
            RiskLevel.CRITICAL ->
                "Critical permission risk detected."

            RiskLevel.HIGH ->
                "High permission risk detected."

            RiskLevel.MEDIUM ->
                "Moderate permission risk detected."

            RiskLevel.LOW ->
                "Low permission risk detected."
        }
    }

    /**
     * Recommended action based on risk level.
     */
    fun getRecommendedAction(
        riskLevel: RiskLevel
    ): String {

        return when (riskLevel) {
            RiskLevel.CRITICAL ->
                "Block application and notify user immediately."

            RiskLevel.HIGH ->
                "Recommend permission review and security scan."

            RiskLevel.MEDIUM ->
                "Monitor application behavior."

            RiskLevel.LOW ->
                "No immediate action required."
        }
    }
}
