package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.roundToInt

/**
 * Cyber Defense Engine
 *
 * Central security orchestration engine responsible for:
 * - Threat aggregation
 * - Defense strategy generation
 * - Incident response coordination
 * - Security posture evaluation
 * - Automated cyber defense actions
 */
class CyberDefenseEngine {

    private val defenseProfiles =
        ConcurrentHashMap<String, DefenseProfile>()

    data class DefenseProfile(
        val profileId: String,
        val threatScore: Int,
        val riskScore: Int,
        val protectionScore: Int,
        val defenseLevel: DefenseLevel,
        val activeThreats: Int,
        val recommendedActions: List<String>,
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class DefenseLevel {
        NORMAL,
        ELEVATED,
        HIGH,
        CRITICAL,
        LOCKDOWN
    }

    /**
     * Creates a cyber defense profile.
     */
    suspend fun evaluateDefensePosture(
        profileId: String,
        threatScore: Int,
        riskScore: Int,
        protectionScore: Int,
        activeThreats: Int
    ): NetworkResult<DefenseProfile> = withContext(Dispatchers.Default) {

        try {

            val defenseLevel = determineDefenseLevel(
                threatScore = threatScore,
                riskScore = riskScore,
                protectionScore = protectionScore,
                activeThreats = activeThreats
            )

            val actions = generateDefenseActions(
                defenseLevel
            )

            val profile = DefenseProfile(
                profileId = profileId,
                threatScore = threatScore,
                riskScore = riskScore,
                protectionScore = protectionScore,
                defenseLevel = defenseLevel,
                activeThreats = activeThreats,
                recommendedActions = actions
            )

            defenseProfiles[profileId] = profile

            NetworkResult.Success(profile)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Cyber defense evaluation failed"
            )
        }
    }

    /**
     * Registers a defense profile.
     */
    fun registerProfile(
        profile: DefenseProfile
    ) {
        defenseProfiles[profile.profileId] = profile
    }

    /**
     * Retrieves a defense profile.
     */
    fun getProfile(
        profileId: String
    ): DefenseProfile? {
        return defenseProfiles[profileId]
    }

    /**
     * Returns all defense profiles.
     */
    fun getProfiles(): List<DefenseProfile> {
        return defenseProfiles.values.toList()
    }

    /**
     * Calculates overall defense score.
     */
    fun calculateDefenseScore(
        threatScore: Int,
        riskScore: Int,
        protectionScore: Int
    ): Int {

        val score =
            protectionScore -
            ((threatScore + riskScore) / 2)

        return score.coerceIn(0, 100)
    }

    /**
     * Determines defense level.
     */
    fun determineDefenseLevel(
        threatScore: Int,
        riskScore: Int,
        protectionScore: Int,
        activeThreats: Int
    ): DefenseLevel {

        return when {

            threatScore >= 90 ||
            riskScore >= 90 ||
            activeThreats >= 10 ->
                DefenseLevel.LOCKDOWN

            threatScore >= 75 ||
            riskScore >= 75 ->
                DefenseLevel.CRITICAL

            threatScore >= 50 ||
            riskScore >= 50 ->
                DefenseLevel.HIGH

            threatScore >= 25 ||
            riskScore >= 25 ->
                DefenseLevel.ELEVATED

            protectionScore >= 80 ->
                DefenseLevel.NORMAL

            else ->
                DefenseLevel.ELEVATED
        }
    }

    /**
     * Returns defense status description.
     */
    fun getDefenseStatus(
        level: DefenseLevel
    ): String {

        return when (level) {
            DefenseLevel.NORMAL ->
                "System operating normally."

            DefenseLevel.ELEVATED ->
                "Elevated monitoring enabled."

            DefenseLevel.HIGH ->
                "High threat awareness active."

            DefenseLevel.CRITICAL ->
                "Critical defense measures enabled."

            DefenseLevel.LOCKDOWN ->
                "Emergency lockdown procedures active."
        }
    }

    /**
     * Generates defense actions.
     */
    fun generateDefenseActions(
        level: DefenseLevel
    ): List<String> {

        return when (level) {

            DefenseLevel.LOCKDOWN -> listOf(
                "Block all suspicious traffic",
                "Restrict sensitive operations",
                "Trigger incident response",
                "Isolate affected components"
            )

            DefenseLevel.CRITICAL -> listOf(
                "Enable advanced threat monitoring",
                "Increase scan frequency",
                "Review active threats"
            )

            DefenseLevel.HIGH -> listOf(
                "Run enhanced security scans",
                "Monitor behavioral anomalies"
            )

            DefenseLevel.ELEVATED -> listOf(
                "Increase security monitoring"
            )

            DefenseLevel.NORMAL -> listOf(
                "Maintain routine monitoring"
            )
        }
    }

    /**
     * Generates remediation summary.
     */
    fun generateRemediationPlan(
        level: DefenseLevel
    ): String {

        return when (level) {

            DefenseLevel.LOCKDOWN ->
                "Immediate remediation and containment required."

            DefenseLevel.CRITICAL ->
                "Urgent threat mitigation required."

            DefenseLevel.HIGH ->
                "Perform detailed security investigation."

            DefenseLevel.ELEVATED ->
                "Review security posture and monitor activity."

            DefenseLevel.NORMAL ->
                "No remediation required."
        }
    }

    /**
     * Calculates average defense score.
     */
    fun calculateAverageDefenseScore(): Int {

        if (defenseProfiles.isEmpty()) {
            return 0
        }

        return defenseProfiles.values
            .map {
                calculateDefenseScore(
                    it.threatScore,
                    it.riskScore,
                    it.protectionScore
                )
            }
            .average()
            .roundToInt()
            .coerceIn(0, 100)
    }

    /**
     * Removes a profile.
     */
    fun removeProfile(
        profileId: String
    ) {
        defenseProfiles.remove(profileId)
    }

    /**
     * Clears all profiles.
     */
    fun clearProfiles() {
        defenseProfiles.clear()
    }

    /**
     * Returns profile count.
     */
    fun getProfileCount(): Int {
        return defenseProfiles.size
    }

    /**
     * Returns profiles in critical state.
     */
    fun getCriticalProfiles(): List<DefenseProfile> {
        return defenseProfiles.values.filter {
            it.defenseLevel == DefenseLevel.CRITICAL ||
            it.defenseLevel == DefenseLevel.LOCKDOWN
        }
    }
}
