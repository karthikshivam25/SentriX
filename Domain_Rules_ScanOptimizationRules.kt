package com.sentrix.domain.rules

/**
 * SentriX Scan Optimization Rules
 *
 * Centralized rules for scan strategy selection,
 * resource optimization, battery preservation,
 * scan prioritization, and intelligent scan scheduling.
 */
object ScanOptimizationRules {

    enum class ScanMode {
        QUICK,
        SMART,
        DEEP,
        CUSTOM
    }

    enum class ScanPriority {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Determine the most appropriate scan mode.
     */
    fun determineScanMode(
        batteryLevel: Int,
        threatCount: Int,
        deviceRiskScore: Int,
        isCharging: Boolean
    ): ScanMode {

        return when {
            threatCount >= 10 ||
                    deviceRiskScore >= 80 ->
                ScanMode.DEEP

            threatCount >= 3 ||
                    deviceRiskScore >= 50 ->
                ScanMode.SMART

            batteryLevel < 20 && !isCharging ->
                ScanMode.QUICK

            else ->
                ScanMode.SMART
        }
    }

    /**
     * Calculate scan priority.
     */
    fun determinePriority(
        threatScore: Int,
        activeThreats: Int
    ): ScanPriority {

        return when {
            threatScore >= 85 ||
                    activeThreats >= 5 ->
                ScanPriority.CRITICAL

            threatScore >= 65 ->
                ScanPriority.HIGH

            threatScore >= 35 ->
                ScanPriority.MEDIUM

            else ->
                ScanPriority.LOW
        }
    }

    /**
     * Estimate scan duration in minutes.
     */
    fun estimateScanDuration(
        scanMode: ScanMode,
        applicationCount: Int
    ): Int {

        return when (scanMode) {

            ScanMode.QUICK ->
                maxOf(1, applicationCount / 50)

            ScanMode.SMART ->
                maxOf(3, applicationCount / 25)

            ScanMode.DEEP ->
                maxOf(5, applicationCount / 10)

            ScanMode.CUSTOM ->
                maxOf(2, applicationCount / 20)
        }
    }

    /**
     * Calculate scan coverage percentage.
     */
    fun calculateCoverage(
        scanMode: ScanMode
    ): Int {

        return when (scanMode) {
            ScanMode.QUICK -> 40
            ScanMode.SMART -> 75
            ScanMode.DEEP -> 100
            ScanMode.CUSTOM -> 60
        }
    }

    /**
     * Determine whether scan should be postponed.
     */
    fun shouldPostponeScan(
        batteryLevel: Int,
        isCharging: Boolean,
        activeThreats: Int
    ): Boolean {

        return batteryLevel < 15 &&
                !isCharging &&
                activeThreats == 0
    }

    /**
     * Determine whether deep scan is required.
     */
    fun requiresDeepScan(
        threatScore: Int,
        malwareDetected: Boolean,
        rootedDevice: Boolean
    ): Boolean {

        return threatScore >= 70 ||
                malwareDetected ||
                rootedDevice
    }

    /**
     * Determine whether realtime scan boost
     * should be enabled.
     */
    fun shouldEnableScanBoost(
        activeThreats: Int,
        threatScore: Int
    ): Boolean {

        return activeThreats > 0 ||
                threatScore >= 75
    }

    /**
     * Calculate scan efficiency score.
     */
    fun calculateEfficiencyScore(
        threatsDetected: Int,
        scannedItems: Int
    ): Double {

        if (scannedItems <= 0) {
            return 0.0
        }

        return (
                threatsDetected.toDouble() /
                        scannedItems.toDouble()
                ) * 100
    }

    /**
     * Determine scan frequency in hours.
     */
    fun determineScanFrequency(
        riskScore: Int
    ): Int {

        return when {
            riskScore >= 85 -> 6
            riskScore >= 65 -> 12
            riskScore >= 40 -> 24
            else -> 48
        }
    }

    /**
     * Generate optimization summary.
     */
    fun getOptimizationSummary(
        scanMode: ScanMode
    ): String {

        return when (scanMode) {

            ScanMode.QUICK ->
                "Quick scan selected for fast threat detection."

            ScanMode.SMART ->
                "Smart scan balances coverage and performance."

            ScanMode.DEEP ->
                "Deep scan provides comprehensive threat analysis."

            ScanMode.CUSTOM ->
                "Custom scan configuration is active."
        }
    }

    /**
     * Recommended scan action.
     */
    fun getRecommendedAction(
        scanMode: ScanMode
    ): String {

        return when (scanMode) {

            ScanMode.QUICK ->
                "Run a quick scan immediately."

            ScanMode.SMART ->
                "Perform a smart scan for balanced protection."

            ScanMode.DEEP ->
                "Run a full deep scan and review findings."

            ScanMode.CUSTOM ->
                "Execute the configured custom scan profile."
        }
    }

    /**
     * Determine whether user should be notified
     * before scan execution.
     */
    fun shouldNotifyBeforeScan(
        scanMode: ScanMode
    ): Boolean {

        return scanMode == ScanMode.DEEP
    }

    /**
     * Calculate overall scan health score.
     */
    fun calculateScanHealthScore(
        lastScanAgeHours: Int,
        riskScore: Int
    ): Int {

        var score = 100

        score -= (lastScanAgeHours / 12)
        score -= (riskScore / 4)

        return score.coerceIn(0, 100)
    }
}
