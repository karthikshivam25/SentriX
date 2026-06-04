package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow

/**
 * Device Integrity Middleware
 * Validates device security posture before allowing
 * sensitive operations to execute.
 *
 * Checks may include:
 * - Root detection
 * - Emulator detection
 * - Debugger detection
 * - Bootloader status
 * - Device attestation
 */
class DeviceIntegrityMiddleware {

    /**
     * Executes a request after device integrity validation.
     */
    suspend fun <T> execute(
        isDeviceTrusted: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isDeviceTrusted) {
            emit(
                NetworkResult.Error(
                    message = "Device integrity validation failed"
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
                        ?: "Device integrity middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected device integrity error"
            )
        )
    }

    /**
     * Determines if the device passes all integrity checks.
     */
    fun isDeviceSecure(
        isRooted: Boolean,
        isEmulator: Boolean,
        isDebuggerAttached: Boolean
    ): Boolean {
        return !isRooted &&
                !isEmulator &&
                !isDebuggerAttached
    }

    /**
     * Calculates a device trust score.
     */
    fun calculateTrustScore(
        isRooted: Boolean,
        isEmulator: Boolean,
        isDebuggerAttached: Boolean,
        isBootloaderUnlocked: Boolean
    ): Int {

        var score = 100

        if (isRooted) score -= 40
        if (isEmulator) score -= 25
        if (isDebuggerAttached) score -= 20
        if (isBootloaderUnlocked) score -= 15

        return score.coerceIn(0, 100)
    }

    /**
     * Returns trust level based on score.
     */
    fun getTrustLevel(
        trustScore: Int
    ): String {
        return when {
            trustScore >= 90 -> "TRUSTED"
            trustScore >= 75 -> "SECURE"
            trustScore >= 50 -> "WARNING"
            trustScore >= 25 -> "HIGH_RISK"
            else -> "UNTRUSTED"
        }
    }

    /**
     * Identifies integrity violations.
     */
    fun detectViolations(
        isRooted: Boolean,
        isEmulator: Boolean,
        isDebuggerAttached: Boolean,
        isBootloaderUnlocked: Boolean
    ): List<String> {

        val violations = mutableListOf<String>()

        if (isRooted) {
            violations.add("Root access detected")
        }

        if (isEmulator) {
            violations.add("Emulator environment detected")
        }

        if (isDebuggerAttached) {
            violations.add("Debugger attached")
        }

        if (isBootloaderUnlocked) {
            violations.add("Bootloader unlocked")
        }

        return violations
    }

    /**
     * Executes operation only on trusted devices.
     */
    suspend fun <T> executeTrusted(
        trustScore: Int,
        minimumTrustScore: Int = 75,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {

            if (trustScore < minimumTrustScore) {
                NetworkResult.Error(
                    message = "Device trust score below required threshold"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }

        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Trusted device execution failed"
            )
        }
    }

    /**
     * Logs integrity-related events.
     */
    fun logIntegrityEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Device Integrity Event: $event")
    }
}
