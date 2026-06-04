package com.sentrix.core.middleware

import com.sentrix.core.wrappers.NetworkResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.flow
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Encryption Middleware
 * Handles encryption validation, secure data processing,
 * and encryption policy enforcement.
 */
class EncryptionMiddleware {

    /**
     * Executes a request after validating encryption requirements.
     */
    suspend fun <T> execute(
        isEncryptionEnabled: Boolean,
        block: suspend () -> T
    ): Flow<NetworkResult<T>> = flow {

        emit(NetworkResult.Loading())

        if (!isEncryptionEnabled) {
            emit(
                NetworkResult.Error(
                    message = "Encryption is required for this operation"
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
                        ?: "Encryption middleware error"
                )
            )
        }
    }.catch { throwable ->
        emit(
            NetworkResult.Error(
                message = throwable.message
                    ?: "Unexpected encryption error"
            )
        )
    }

    /**
     * Validates encryption key requirements.
     */
    fun isValidKey(
        key: String?
    ): Boolean {
        return !key.isNullOrBlank() &&
                key.length in listOf(16, 24, 32)
    }

    /**
     * Encrypts plain text using AES.
     */
    fun encrypt(
        plainText: String,
        secretKey: String
    ): String {
        require(isValidKey(secretKey)) {
            "Invalid encryption key length"
        }

        val cipher = Cipher.getInstance("AES")
        val keySpec = SecretKeySpec(
            secretKey.toByteArray(),
            "AES"
        )

        cipher.init(Cipher.ENCRYPT_MODE, keySpec)

        return Base64.getEncoder().encodeToString(
            cipher.doFinal(plainText.toByteArray())
        )
    }

    /**
     * Decrypts AES encrypted text.
     */
    fun decrypt(
        encryptedText: String,
        secretKey: String
    ): String {
        require(isValidKey(secretKey)) {
            "Invalid encryption key length"
        }

        val cipher = Cipher.getInstance("AES")
        val keySpec = SecretKeySpec(
            secretKey.toByteArray(),
            "AES"
        )

        cipher.init(Cipher.DECRYPT_MODE, keySpec)

        return String(
            cipher.doFinal(
                Base64.getDecoder().decode(encryptedText)
            )
        )
    }

    /**
     * Calculates encryption strength score.
     */
    fun calculateEncryptionStrength(
        keyLength: Int
    ): Int {
        return when {
            keyLength >= 32 -> 100
            keyLength >= 24 -> 80
            keyLength >= 16 -> 60
            else -> 0
        }
    }

    /**
     * Returns encryption security level.
     */
    fun getSecurityLevel(
        strengthScore: Int
    ): String {
        return when {
            strengthScore >= 90 -> "MAXIMUM"
            strengthScore >= 75 -> "HIGH"
            strengthScore >= 50 -> "MEDIUM"
            strengthScore > 0 -> "LOW"
            else -> "UNSECURED"
        }
    }

    /**
     * Executes operation only when encryption policy is satisfied.
     */
    suspend fun <T> executeSecure(
        secretKey: String?,
        block: suspend () -> T
    ): NetworkResult<T> {
        return try {
            if (!isValidKey(secretKey)) {
                NetworkResult.Error(
                    message = "Encryption key validation failed"
                )
            } else {
                NetworkResult.Success(block.invoke())
            }
        } catch (exception: Exception) {
            NetworkResult.Error(
                message = exception.message
                    ?: "Secure encryption execution failed"
            )
        }
    }

    /**
     * Logs encryption-related events.
     */
    fun logEncryptionEvent(
        event: String,
        logger: (String) -> Unit
    ) {
        logger.invoke("Encryption Event: $event")
    }
}
