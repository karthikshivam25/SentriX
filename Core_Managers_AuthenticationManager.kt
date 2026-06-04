package com.sentrix.core.managers

import android.content.Context
import android.util.Patterns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.util.UUID

/**
 * AuthenticationManager
 *
 * Handles:
 * - User registration
 * - Login validation
 * - Password hashing
 * - Session creation
 * - Logout
 * - Authentication state
 *
 * NOTE:
 * This implementation is intended as a local authentication layer.
 * For production environments, integrate with a secure backend,
 * OAuth provider, Firebase Auth, or enterprise IAM solution.
 */
class AuthenticationManager(
    private val context: Context,
    private val sessionManager: SessionManager
) {

    private var currentUser: AuthUser? = null

    /**
     * Register a user.
     */
    suspend fun register(
        email: String,
        password: String
    ): AuthResult = withContext(Dispatchers.Default) {

        if (!isValidEmail(email)) {
            return@withContext AuthResult.Error(
                "Invalid email address."
            )
        }

        if (!isStrongPassword(password)) {
            return@withContext AuthResult.Error(
                "Password must contain at least 8 characters, one uppercase letter, one lowercase letter, and one digit."
            )
        }

        val user = AuthUser(
            id = UUID.randomUUID().toString(),
            email = email,
            passwordHash = hashPassword(password),
            createdAt = System.currentTimeMillis()
        )

        currentUser = user

        AuthResult.Success(user)
    }

    /**
     * Login user.
     */
    suspend fun login(
        email: String,
        password: String
    ): AuthResult = withContext(Dispatchers.Default) {

        val user = currentUser

        if (user == null) {
            return@withContext AuthResult.Error(
                "User not found."
            )
        }

        if (!user.email.equals(email, ignoreCase = true)) {
            return@withContext AuthResult.Error(
                "Invalid credentials."
            )
        }

        if (user.passwordHash != hashPassword(password)) {
            return@withContext AuthResult.Error(
                "Invalid credentials."
            )
        }

        val authToken = UUID.randomUUID().toString()

        sessionManager.createSession(
            userId = user.id,
            authToken = authToken
        )

        AuthResult.Success(user)
    }

    /**
     * Logout current user.
     */
    fun logout() {
        sessionManager.logout()
    }

    /**
     * Returns authentication state.
     */
    fun isAuthenticated(): Boolean {
        return sessionManager.isSessionActive()
    }

    /**
     * Returns current logged-in user.
     */
    fun getCurrentUser(): AuthUser? {
        return if (isAuthenticated()) currentUser else null
    }

    /**
     * Validate email format.
     */
    fun isValidEmail(email: String): Boolean {
        return Patterns.EMAIL_ADDRESS.matcher(email).matches()
    }

    /**
     * Validate password strength.
     */
    fun isStrongPassword(password: String): Boolean {

        val hasUppercase = password.any { it.isUpperCase() }
        val hasLowercase = password.any { it.isLowerCase() }
        val hasDigit = password.any { it.isDigit() }

        return password.length >= 8 &&
                hasUppercase &&
                hasLowercase &&
                hasDigit
    }

    /**
     * Hash password using SHA-256.
     */
    fun hashPassword(password: String): String {

        val digest =
            MessageDigest.getInstance("SHA-256")

        val hashBytes =
            digest.digest(password.toByteArray())

        return hashBytes.joinToString("") {
            "%02x".format(it)
        }
    }

    /**
     * Change password.
     */
    suspend fun changePassword(
        oldPassword: String,
        newPassword: String
    ): AuthResult = withContext(Dispatchers.Default) {

        val user = currentUser
            ?: return@withContext AuthResult.Error(
                "No authenticated user."
            )

        if (user.passwordHash != hashPassword(oldPassword)) {
            return@withContext AuthResult.Error(
                "Old password is incorrect."
            )
        }

        if (!isStrongPassword(newPassword)) {
            return@withContext AuthResult.Error(
                "New password does not meet security requirements."
            )
        }

        currentUser = user.copy(
            passwordHash = hashPassword(newPassword)
        )

        AuthResult.Success(currentUser!!)
    }

    /**
     * Clear authentication data.
     */
    fun clearAuthentication() {
        currentUser = null
        sessionManager.logout()
    }

    /**
     * User model.
     */
    data class AuthUser(
        val id: String,
        val email: String,
        val passwordHash: String,
        val createdAt: Long
    )

    /**
     * Authentication result.
     */
    sealed class AuthResult {

        data class Success(
            val user: AuthUser
        ) : AuthResult()

        data class Error(
            val message: String
        ) : AuthResult()
    }
}
