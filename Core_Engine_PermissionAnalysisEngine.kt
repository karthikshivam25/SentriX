package com.sentrix.core.engine

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Permission Analysis Engine
 *
 * Responsible for:
 * - Permission risk assessment
 * - Dangerous permission detection
 * - Permission behavior analysis
 * - Permission compliance evaluation
 * - Security recommendations
 */
class PermissionAnalysisEngine {

    private val analyzedPermissions =
        ConcurrentHashMap<String, PermissionRecord>()

    data class PermissionRecord(
        val permission: String,
        val riskScore: Int,
        val category: String,
        val timestamp: Long = System.currentTimeMillis()
    )

    /**
     * Analyzes application permissions.
     */
    suspend fun analyzePermissions(
        permissions: List<String>
    ): NetworkResult<List<PermissionRecord>> = withContext(Dispatchers.Default) {

        try {

            val records = permissions.map { permission ->

                PermissionRecord(
                    permission = permission,
                    riskScore = calculatePermissionRisk(permission),
                    category = categorizePermission(permission)
                )
            }

            records.forEach {
                analyzedPermissions[it.permission] = it
            }

            NetworkResult.Success(records)

        } catch (exception: Exception) {

            NetworkResult.Error(
                message = exception.message
                    ?: "Permission analysis failed"
            )
        }
    }

    /**
     * Registers a permission record.
     */
    fun registerPermission(
        record: PermissionRecord
    ) {
        analyzedPermissions[record.permission] = record
    }

    /**
     * Retrieves permission information.
     */
    fun getPermission(
        permission: String
    ): PermissionRecord? {
        return analyzedPermissions[permission]
    }

    /**
     * Returns all analyzed permissions.
     */
    fun getAnalyzedPermissions(): List<PermissionRecord> {
        return analyzedPermissions.values.toList()
    }

    /**
     * Calculates overall permission risk score.
     */
    fun calculateOverallRiskScore(): Int {

        if (analyzedPermissions.isEmpty()) {
            return 0
        }

        return analyzedPermissions.values
            .map { it.riskScore }
            .average()
            .toInt()
            .coerceIn(0, 100)
    }

    /**
     * Detects dangerous permissions.
     */
    fun getDangerousPermissions(): List<PermissionRecord> {
        return analyzedPermissions.values.filter {
            it.riskScore >= 75
        }
    }

    /**
     * Determines risk level.
     */
    fun getRiskLevel(
        score: Int
    ): String {
        return when {
            score >= 90 -> "CRITICAL"
            score >= 75 -> "HIGH"
            score >= 50 -> "MEDIUM"
            score >= 25 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Generates security recommendations.
     */
    fun generateRecommendations(): List<String> {

        val recommendations = mutableListOf<String>()

        val dangerousPermissions =
            getDangerousPermissions()

        if (dangerousPermissions.isNotEmpty()) {
            recommendations.add(
                "Review high-risk permissions."
            )
        }

        if (calculateOverallRiskScore() >= 75) {
            recommendations.add(
                "Restrict unnecessary permissions."
            )
        }

        if (recommendations.isEmpty()) {
            recommendations.add(
                "Permission configuration appears safe."
            )
        }

        return recommendations
    }

    /**
     * Removes a permission record.
     */
    fun removePermission(
        permission: String
    ) {
        analyzedPermissions.remove(permission)
    }

    /**
     * Clears analysis cache.
     */
    fun clearPermissions() {
        analyzedPermissions.clear()
    }

    /**
     * Returns analyzed permission count.
     */
    fun getPermissionCount(): Int {
        return analyzedPermissions.size
    }

    /**
     * Categorizes permission type.
     */
    private fun categorizePermission(
        permission: String
    ): String {

        return when {
            permission.contains("CAMERA", true) ->
                "HARDWARE"

            permission.contains("LOCATION", true) ->
                "LOCATION"

            permission.contains("SMS", true) ->
                "COMMUNICATION"

            permission.contains("CONTACT", true) ->
                "PERSONAL_DATA"

            permission.contains("MICROPHONE", true) ||
            permission.contains("RECORD_AUDIO", true) ->
                "AUDIO"

            permission.contains("STORAGE", true) ->
                "STORAGE"

            else -> "GENERAL"
        }
    }

    /**
     * Calculates permission risk score.
     */
    private fun calculatePermissionRisk(
        permission: String
    ): Int {

        return when {
            permission.contains("READ_SMS", true) -> 95

            permission.contains("SEND_SMS", true) -> 95

            permission.contains("READ_CONTACTS", true) -> 85

            permission.contains("ACCESS_FINE_LOCATION", true) -> 80

            permission.contains("RECORD_AUDIO", true) -> 75

            permission.contains("CAMERA", true) -> 65

            permission.contains("READ_EXTERNAL_STORAGE", true) -> 60

            else -> 25
        }
    }
}
