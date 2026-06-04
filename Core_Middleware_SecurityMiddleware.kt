package com.sentrix.core.middleware

import android.util.Log
import com.sentrix.core.enums.SecurityStatus
import com.sentrix.core.helpers.RootDetectionHelper
import com.sentrix.core.helpers.VPNHelper
import com.sentrix.core.managers.SecurityManager
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Central security middleware responsible for enforcing
 * application-wide security policies before sensitive
 * operations are executed.
 */
@Singleton
class SecurityMiddleware @Inject constructor(
    private val securityManager: SecurityManager,
    private val rootDetectionHelper: RootDetectionHelper,
    private val vpnHelper: VPNHelper
) {

    /**
     * Executes security validation before allowing
     * protected operations.
     */
    @Throws(SecurityViolationException::class)
    fun validateSecurity() {

        val violations = mutableListOf<String>()

        if (rootDetectionHelper.isDeviceRooted()) {
            violations.add("Rooted device detected")
        }

        if (securityManager.isTampered()) {
            violations.add("Application tampering detected")
        }

        if (securityManager.isDebuggerAttached()) {
            violations.add("Debugger detected")
        }

        if (securityManager.isEmulator()) {
            violations.add("Emulator environment detected")
        }

        if (securityManager.isDeveloperModeEnabled()) {
            violations.add("Developer options enabled")
        }

        if (securityManager.requiresVpnProtection() &&
            !vpnHelper.isVpnConnected()
        ) {
            violations.add("VPN protection required")
        }

        if (violations.isNotEmpty()) {

            Log.e(
                TAG,
                """
                Security Validation Failed
                --------------------------
                Violations:
                ${violations.joinToString("\n")}
                """.trimIndent()
            )

            throw SecurityViolationException(
                violations.joinToString(separator = " | ")
            )
        }
    }

    /**
     * Returns current device security status.
     */
    fun getSecurityStatus(): SecurityStatus {

        return when {
            rootDetectionHelper.isDeviceRooted() ->
                SecurityStatus.COMPROMISED

            securityManager.isTampered() ->
                SecurityStatus.COMPROMISED

            securityManager.isDebuggerAttached() ->
                SecurityStatus.WARNING

            securityManager.isDeveloperModeEnabled() ->
                SecurityStatus.WARNING

            else ->
                SecurityStatus.SECURE
        }
    }

    /**
     * Executes a protected action only after
     * successful security validation.
     */
    inline fun <T> executeSecure(
        action: () -> T
    ): T {

        validateSecurity()

        return action()
    }

    companion object {
        private const val TAG = "SentriX-SecurityMiddleware"
    }
}

/**
 * Thrown when security validation fails.
 */
class SecurityViolationException(
    message: String
) : SecurityException(message)
