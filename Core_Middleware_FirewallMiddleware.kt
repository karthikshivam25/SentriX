package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.net.InetAddress

/**
 * Firewall Middleware
 * Monitors and controls network traffic based on
 * predefined security rules and policies.
 */
class FirewallMiddleware {

    /**
     * Executes a request after firewall validation.
     */
    suspend fun <T> execute(
        isTrafficAllowed: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isTrafficAllowed) {
            emit(
                NetworkResult.Error(
                    message = "Firewall blocked the request"
                )
            )
            return@flow
        }

        try {
            val result = block.invoke()
            emit(NetworkResult.Success(result))
        } catch (exception: Exception) {
            emit(
                NetworkResult.Error(
                    message = exception.message
                        ?: "Firewall middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected firewall error"
            )
        )
    }

    /**
     * Checks if an IP address is allowed.
     */
    fun isIpAllowed(
        ipAddress: String,
        whitelist: List<String>
    ): Boolean {
        return whitelist.isEmpty() ||
                whitelist.contains(ipAddress)
    }

    /**
     * Checks if an IP address is blocked.
     */
    fun isIpBlocked(
        ipAddress: String,
        blacklist: List<String>
    ): Boolean {
        return blacklist.contains(ipAddress)
    }

    /**
     * Validates a host address.
     */
    fun isValidHost(
        host: String
    ): Boolean {
        return try {
            InetAddress.getByName(host)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Calculates firewall risk score.
     */
    fun calculateRiskScore(
        isBlacklisted: Boolean,
        suspiciousRequests: Int,
        failedAttempts: Int
    ): Int {

        var score = 0

        if (isBlacklisted) score += 60
        score += suspiciousRequests * 5
        score += failedAttempts * 3

        return score.coerceIn(0, 100)
    }

    /**
     * Returns firewall security level.
     */
    fun getSecurityLevel(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 80 -> "CRITICAL"
            riskScore >= 60 -> "HIGH"
            riskScore >= 40 -> "MEDIUM"
            riskScore >= 20 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Determines whether a request should be blocked.
     */
    fun shouldBlockRequest(
        riskScore: Int,
        threshold: Int = 60
    ): Boolean {
        return riskScore >= threshold
    }

    /**
     * Executes operation only if firewall policies pass.
     */
    suspend fun <T> executeProtected(
        ipAddress: String,
        blacklist: List<String>,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            if (isIpBlocked(ipAddress, blacklist)) {
                NetworkResult.Error(
                    message = "Request blocked by firewall policy"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }

        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Firewall protected execution failed"
            )
        }
    }

    /**
     * Logs firewall-related events.
     */
    fun logFirewallEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Firewall Event: $event")
    }
}
