package com.sentrix.core.helpers

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

object BiometricsHelper {

    /**
     * Check if biometric authentication is available
     */
    fun isBiometricAvailable(
        context: Context
    ): Boolean {

        val biometricManager = BiometricManager.from(context)

        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Check if device has biometric hardware
     */
    fun hasBiometricHardware(
        context: Context
    ): Boolean {

        val biometricManager = BiometricManager.from(context)

        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        ) != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE
    }

    /**
     * Check if user enrolled biometrics
     */
    fun hasEnrolledBiometrics(
        context: Context
    ): Boolean {

        val biometricManager = BiometricManager.from(context)

        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        ) != BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
    }

    /**
     * Get biometric availability status message
     */
    fun getBiometricStatus(
        context: Context
    ): String {

        val biometricManager = BiometricManager.from(context)

        return when (
            biometricManager.canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.BIOMETRIC_WEAK
            )
        ) {

            BiometricManager.BIOMETRIC_SUCCESS -> {
                "Biometric authentication available"
            }

            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                "No biometric hardware found"
            }

            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                "Biometric hardware unavailable"
            }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                "No biometrics enrolled"
            }

            else -> {
                "Biometric authentication unsupported"
            }
        }
    }

    /**
     * Create biometric prompt info
     */
    fun createPromptInfo(
        title: String,
        subtitle: String,
        negativeButtonText: String = "Cancel"
    ): BiometricPrompt.PromptInfo {

        return BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText(negativeButtonText)
            .build()
    }

    /**
     * Authenticate user with biometrics
     */
    fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
        onFailed: () -> Unit = {}
    ) {

        val executor = ContextCompat.getMainExecutor(activity)

        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess.invoke()
                }

                override fun onAuthenticationError(
                    errorCode: Int,
                    errString: CharSequence
                ) {
                    super.onAuthenticationError(errorCode, errString)
                    onError.invoke(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onFailed.invoke()
                }
            }
        )

        val promptInfo = createPromptInfo(
            title = title,
            subtitle = subtitle
        )

        biometricPrompt.authenticate(promptInfo)
    }

    /**
     * Check if strong biometrics supported
     */
    fun supportsStrongBiometrics(
        context: Context
    ): Boolean {

        val biometricManager = BiometricManager.from(context)

        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Check if weak biometrics supported
     */
    fun supportsWeakBiometrics(
        context: Context
    ): Boolean {

        val biometricManager = BiometricManager.from(context)

        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        ) == BiometricManager.BIOMETRIC_SUCCESS
    }
}
