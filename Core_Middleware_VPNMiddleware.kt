package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * VPN Middleware
 * Validates VPN status and enforces VPN-related security policies
 * before executing protected operations.
 */
class VPNMiddleware {

    /**
     * Executes a request after VPN validation.
     */
    suspend fun <T> execute(
        isVpnConnected: Boolean,
        requireVpn: Boolean = false,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (requireVpn && !isVpnConnected) {
            emit(
                NetworkResult.Error(
                    message = "VPN connection required to proceed"
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
                    message = exception.message ?: "VPN middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message ?: "Unexpected VPN error"
            )
        )
    }

    /**
     * Checks whether VPN connection is active.
     */
    fun isVpnActive(
        vpnStatus: Boolean
    ): Boolean {
        return vpnStatus
    }

    /**
     * Determines if VPN usage is secure.
     */
    fun isSecureVpn(
        providerName: String?,
        trustedProviders: List<String>
    ): Boolean {
        if (providerName.isNullOrBlank()) return false

        return trustedProviders.any {
            it.equals(providerName, ignoreCase = true)
        }
    }

    /**
     * Calculates VPN risk score.
     */
    fun calculateRiskScore(
        isConnected: Boolean,
        isTrustedProvider: Boolean
    ): Int {
        return when {
            !isConnected -> 100
            !isTrustedProvider -> 50
            else -> 0
        }
    }

    /**
     * Returns VPN security level.
     */
    fun getSecurityLevel(
        riskScore: Int
    ): String {
        return when {
            riskScore >= 80 -> "CRITICAL"
            riskScore >= 50 -> "HIGH"
            riskScore >= 20 -> "MEDIUM"
            riskScore > 0 -> "LOW"
            else -> "SAFE"
        }
    }

    /**
     * Executes only when VPN requirements are satisfied.
     */
    suspend fun <T> executeProtected(
        isVpnConnected: Boolean,
        requireVpn: Boolean,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            if (requireVpn && !isVpnConnected) {
                NetworkResult.Error("VPN is required")
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                exception.message ?: "Protected execution failed"
            )
        }
    }

    /**
     * Logs VPN-related events.
     */
    fun logVpnEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("VPN Event: $event")
    }
}
