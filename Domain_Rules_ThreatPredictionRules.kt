package com.sentrix.domain.rules

/**
 * SentriX Threat Prediction Rules
 *
 * Predicts future security threats based on
 * historical threat activity, behavioral patterns,
 * device trust metrics, and current risk indicators.
 */
object ThreatPredictionRules {

    enum class PredictionLevel {
        LOW,
        MODERATE,
        HIGH,
        CRITICAL
    }

    enum class PredictedThreatType {
        MALWARE_INFECTION,
        PHISHING_ATTACK,
        SCAM_ATTEMPT,
        ACCOUNT_COMPROMISE,
        NETWORK_ATTACK,
        DATA_LEAK,
        DEVICE_COMPROMISE,
        UNKNOWN
    }

    /**
     * Calculate predictive threat score.
     */
    fun calculatePredictionScore(
        historicalThreatCount: Int,
        activeThreatCount: Int,
        suspiciousBehaviorCount: Int,
        deviceTrustScore: Int,
        networkRiskScore: Int,
        recentSecurityIncidents: Int
    ): Int {

        var score = 0

        score += historicalThreatCount * 2
        score += activeThreatCount * 8
        score += suspiciousBehaviorCount * 5
        score += recentSecurityIncidents * 10

        score += (100 - deviceTrustScore) / 2
        score += networkRiskScore / 2

        return score.coerceIn(0, 100)
    }

    /**
     * Determine threat prediction level.
     */
    fun determinePredictionLevel(
        predictionScore: Int
    ): PredictionLevel {

        return when {
            predictionScore >= 80 -> PredictionLevel.CRITICAL
            predictionScore >= 60 -> PredictionLevel.HIGH
            predictionScore >= 35 -> PredictionLevel.MODERATE
            else -> PredictionLevel.LOW
        }
    }

    /**
     * Predict most likely threat type.
     */
    fun predictThreatType(
        malwareIndicators: Int,
        phishingIndicators: Int,
        scamIndicators: Int,
        networkIndicators: Int,
        deviceIntegrityIssues: Int
    ): PredictedThreatType {

        val highestScore = listOf(
            malwareIndicators,
            phishingIndicators,
            scamIndicators,
            networkIndicators,
            deviceIntegrityIssues
        ).maxOrNull() ?: 0

        return when (highestScore) {

            malwareIndicators ->
                PredictedThreatType.MALWARE_INFECTION

            phishingIndicators ->
                PredictedThreatType.PHISHING_ATTACK

            scamIndicators ->
                PredictedThreatType.SCAM_ATTEMPT

            networkIndicators ->
                PredictedThreatType.NETWORK_ATTACK

            deviceIntegrityIssues ->
                PredictedThreatType.DEVICE_COMPROMISE

            else ->
                PredictedThreatType.UNKNOWN
        }
    }

    /**
     * Calculate prediction confidence.
     */
    fun calculateConfidence(
        matchedIndicators: Int,
        totalIndicators: Int
    ): Double {

        if (totalIndicators <= 0) {
            return 0.0
        }

        return (matchedIndicators.toDouble() /
                totalIndicators.toDouble())
            .coerceIn(0.0, 1.0)
    }

    /**
     * Check if proactive protection should be enabled.
     */
    fun shouldEnableProactiveProtection(
        predictionLevel: PredictionLevel
    ): Boolean {

        return predictionLevel == PredictionLevel.HIGH ||
                predictionLevel == PredictionLevel.CRITICAL
    }

    /**
     * Check if additional monitoring is required.
     */
    fun requiresEnhancedMonitoring(
        predictionLevel: PredictionLevel
    ): Boolean {

        return predictionLevel == PredictionLevel.MODERATE ||
                predictionLevel == PredictionLevel.HIGH ||
                predictionLevel == PredictionLevel.CRITICAL
    }

    /**
     * Determine if threat escalation is likely.
     */
    fun isThreatEscalationLikely(
        activeThreatCount: Int,
        recentSecurityIncidents: Int
    ): Boolean {

        return activeThreatCount >= 3 ||
                recentSecurityIncidents >= 2
    }

    /**
     * Generate prediction summary.
     */
    fun getPredictionSummary(
        level: PredictionLevel,
        threatType: PredictedThreatType
    ): String {

        return when (level) {

            PredictionLevel.LOW ->
                "Low probability of future threats."

            PredictionLevel.MODERATE ->
                "Moderate likelihood of $threatType."

            PredictionLevel.HIGH ->
                "High probability of $threatType."

            PredictionLevel.CRITICAL ->
                "Critical threat prediction: $threatType."
        }
    }

    /**
     * Get recommended preventive action.
     */
    fun getRecommendedAction(
        level: PredictionLevel
    ): String {

        return when (level) {

            PredictionLevel.LOW ->
                "Continue normal monitoring."

            PredictionLevel.MODERATE ->
                "Increase monitoring and review security posture."

            PredictionLevel.HIGH ->
                "Enable proactive protection and perform security checks."

            PredictionLevel.CRITICAL ->
                "Activate maximum protection and notify the user immediately."
        }
    }

    /**
     * Determine whether prediction alert should be generated.
     */
    fun requiresPredictionAlert(
        level: PredictionLevel
    ): Boolean {

        return level == PredictionLevel.HIGH ||
                level == PredictionLevel.CRITICAL
    }

    /**
     * Calculate overall future risk percentage.
     */
    fun calculateFutureRiskPercentage(
        predictionScore: Int
    ): Double {

        return predictionScore.toDouble()
    }
}
