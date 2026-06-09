package com.sentrix.domain.rules

/**
 * SentriX Alert Priority Rules
 *
 * Centralized alert prioritization engine responsible for
 * assigning alert severity, escalation levels, notification
 * urgency, and response priorities.
 */
object AlertPriorityRules {

    enum class AlertPriority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum class AlertCategory {
        THREAT,
        MALWARE,
        NETWORK,
        DEVICE_TRUST,
        COMPLIANCE,
        POLICY,
        SYSTEM,
        REALTIME_PROTECTION
    }

    /**
     * Determine alert priority from risk score.
     */
    fun determinePriority(
        riskScore: Int
    ): AlertPriority {

        return when {
            riskScore >= 85 ->
                AlertPriority.CRITICAL

            riskScore >= 65 ->
                AlertPriority.HIGH

            riskScore >= 40 ->
                AlertPriority.MEDIUM

            else ->
                AlertPriority.LOW
        }
    }

    /**
     * Determine alert priority from threat severity.
     */
    fun determinePriority(
        threatSeverity: ThreatSeverityRules.ThreatSeverity
    ): AlertPriority {

        return when (threatSeverity) {
            ThreatSeverityRules.ThreatSeverity.CRITICAL ->
                AlertPriority.CRITICAL

            ThreatSeverityRules.ThreatSeverity.HIGH ->
                AlertPriority.HIGH

            ThreatSeverityRules.ThreatSeverity.MEDIUM ->
                AlertPriority.MEDIUM

            ThreatSeverityRules.ThreatSeverity.LOW ->
                AlertPriority.LOW
        }
    }

    /**
     * Calculate alert score.
     */
    fun calculateAlertScore(
        riskScore: Int,
        activeThreats: Int,
        confidenceScore: Double
    ): Int {

        val score =
            riskScore +
            (activeThreats * 5) +
            (confidenceScore * 20).toInt()

        return score.coerceIn(0, 100)
    }

    /**
     * Determine if immediate user notification is required.
     */
    fun requiresImmediateNotification(
        priority: AlertPriority
    ): Boolean {

        return priority == AlertPriority.HIGH ||
                priority == AlertPriority.CRITICAL
    }

    /**
     * Determine if alert escalation is required.
     */
    fun requiresEscalation(
        priority: AlertPriority
    ): Boolean {

        return priority == AlertPriority.CRITICAL
    }

    /**
     * Determine if alert should trigger emergency response.
     */
    fun requiresEmergencyResponse(
        priority: AlertPriority
    ): Boolean {

        return priority == AlertPriority.CRITICAL
    }

    /**
     * Determine alert retention period in days.
     */
    fun getRetentionPeriodDays(
        priority: AlertPriority
    ): Int {

        return when (priority) {
            AlertPriority.LOW -> 7
            AlertPriority.MEDIUM -> 30
            AlertPriority.HIGH -> 90
            AlertPriority.CRITICAL -> 365
        }
    }

    /**
     * Determine alert response SLA in minutes.
     */
    fun getResponseSlaMinutes(
        priority: AlertPriority
    ): Int {

        return when (priority) {
            AlertPriority.LOW -> 1440      // 24 hours
            AlertPriority.MEDIUM -> 240    // 4 hours
            AlertPriority.HIGH -> 60       // 1 hour
            AlertPriority.CRITICAL -> 15
        }
    }

    /**
     * Determine notification channel.
     */
    fun getNotificationChannel(
        priority: AlertPriority
    ): String {

        return when (priority) {
            AlertPriority.LOW ->
                "IN_APP"

            AlertPriority.MEDIUM ->
                "IN_APP_AND_PUSH"

            AlertPriority.HIGH ->
                "PUSH_AND_EMAIL"

            AlertPriority.CRITICAL ->
                "ALL_CHANNELS"
        }
    }

    /**
     * Generate alert title.
     */
    fun generateAlertTitle(
        category: AlertCategory,
        priority: AlertPriority
    ): String {

        return "${priority.name} ${category.name.replace("_", " ")} ALERT"
    }

    /**
     * Generate alert description.
     */
    fun generateAlertDescription(
        category: AlertCategory,
        priority: AlertPriority
    ): String {

        return when (priority) {

            AlertPriority.LOW ->
                "Minor security event detected in $category."

            AlertPriority.MEDIUM ->
                "Security attention required for $category."

            AlertPriority.HIGH ->
                "High-risk security event detected in $category."

            AlertPriority.CRITICAL ->
                "Critical security incident detected in $category."
        }
    }

    /**
     * Determine whether alert should be logged.
     */
    fun shouldLogAlert(
        priority: AlertPriority
    ): Boolean {
        return true
    }

    /**
     * Determine whether alert should be displayed to user.
     */
    fun shouldDisplayToUser(
        priority: AlertPriority
    ): Boolean {

        return priority != AlertPriority.LOW
    }

    /**
     * Calculate alert confidence level.
     */
    fun calculateConfidenceLevel(
        matchedIndicators: Int,
        totalIndicators: Int
    ): Double {

        if (totalIndicators <= 0) {
            return 0.0
        }

        return matchedIndicators.toDouble() /
                totalIndicators.toDouble()
    }

    /**
     * Generate alert summary.
     */
    fun getAlertSummary(
        priority: AlertPriority
    ): String {

        return when (priority) {

            AlertPriority.LOW ->
                "Low-priority security alert."

            AlertPriority.MEDIUM ->
                "Medium-priority security alert."

            AlertPriority.HIGH ->
                "High-priority security alert."

            AlertPriority.CRITICAL ->
                "Critical-priority security alert."
        }
    }
}
