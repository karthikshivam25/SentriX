package com.sentrix.data.remote.api

import com.sentrix.data.remote.dto.auth.LoginRequestDto
import com.sentrix.data.remote.dto.auth.LoginResponseDto
import com.sentrix.data.remote.dto.auth.RefreshTokenRequestDto
import com.sentrix.data.remote.dto.auth.RegisterRequestDto
import com.sentrix.data.remote.dto.auth.RegisterResponseDto
import com.sentrix.data.remote.dto.auth.ResetPasswordRequestDto
import com.sentrix.data.remote.dto.auth.ForgotPasswordRequestDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.POST

/**
 * AuthApiService
 *
 * Retrofit API service responsible for all
 * authentication and authorization operations.
 *
 * Features:
 * - User Registration
 * - User Login
 * - Token Refresh
 * - Forgot Password
 * - Password Reset
 * - Session Management
 *
 * Used By:
 * - AuthenticationRepository
 * - AuthenticationService
 * - SessionService
 * - LoginViewModel
 * - RegisterViewModel
 *
 * Base URL Example:
 * https://api.sentrix.com/
 */
interface AuthApiService {

    /**
     * Register a new SentriX user.
     *
     * Endpoint:
     * POST /auth/register
     */
    @POST("auth/register")
    suspend fun register(
        @Body request: RegisterRequestDto
    ): Response<RegisterResponseDto>

    /**
     * Authenticate user credentials.
     *
     * Endpoint:
     * POST /auth/login
     */
    @POST("auth/login")
    suspend fun login(
        @Body request: LoginRequestDto
    ): Response<LoginResponseDto>

    /**
     * Refresh access token using
     * a valid refresh token.
     *
     * Endpoint:
     * POST /auth/refresh-token
     */
    @POST("auth/refresh-token")
    suspend fun refreshToken(
        @Body request: RefreshTokenRequestDto
    ): Response<LoginResponseDto>

    /**
     * Send password reset email or OTP.
     *
     * Endpoint:
     * POST /auth/forgot-password
     */
    @POST("auth/forgot-password")
    suspend fun forgotPassword(
        @Body request: ForgotPasswordRequestDto
    ): Response<Unit>

    /**
     * Reset user password.
     *
     * Endpoint:
     * POST /auth/reset-password
     */
    @POST("auth/reset-password")
    suspend fun resetPassword(
        @Body request: ResetPasswordRequestDto
    ): Response<Unit>

    /**
     * Logout current user session.
     *
     * Endpoint:
     * POST /auth/logout
     */
    @POST("auth/logout")
    suspend fun logout(): Response<Unit>
}
