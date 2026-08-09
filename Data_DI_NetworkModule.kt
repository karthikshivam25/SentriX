package com.sentrix.data.di

import android.content.Context
import com.sentrix.data.remote.api.AnalyticsApiService
import com.sentrix.data.remote.api.AuthApiService
import com.sentrix.data.remote.api.PrivacyApiService
import com.sentrix.data.remote.api.ReportApiService
import com.sentrix.data.remote.api.ScanApiService
import com.sentrix.data.remote.api.SecurityApiService
import com.sentrix.data.remote.api.ThreatApiService
import com.sentrix.data.remote.api.VPNApiService
import com.sentrix.data.remote.api.DeviceTrustApiService
import com.sentrix.data.remote.interceptors.ApiKeyInterceptor
import com.sentrix.data.remote.interceptors.AuthInterceptor
import com.sentrix.data.remote.interceptors.LoggingInterceptor
import com.sentrix.data.remote.interceptors.NetworkStatusInterceptor
import com.sentrix.data.remote.interceptors.RetryInterceptor
import com.sentrix.data.remote.interceptors.SecurityHeaderInterceptor
import com.sentrix.data.remote.interceptors.ThreatTelemetryInterceptor
import com.sentrix.data.remote.websockets.WebSocketManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import okhttp3.MediaType.Companion.toMediaType
import javax.inject.Named
import javax.inject.Singleton
import java.util.concurrent.TimeUnit

/**
 * SentriX - Network Dependency Injection Module
 *
 * Package:
 * com.sentrix.data.di
 *
 * Responsibility
 * ------------------------------------------------------------
 * Provides the complete networking infrastructure for SentriX.
 *
 * Main responsibilities:
 *
 * - Configure JSON serialization.
 * - Configure OkHttp.
 * - Register security interceptors.
 * - Configure Retrofit.
 * - Provide API service implementations.
 * - Provide WebSocketManager.
 *
 * Network architecture:
 *
 *                  NetworkModule
 *                        │
 *              ┌─────────┴─────────┐
 *              │                   │
 *              ▼                   ▼
 *          OkHttpClient         Retrofit
 *              │                   │
 *       ┌──────┼──────┐            │
 *       │      │      │            │
 *       ▼      ▼      ▼            ▼
 *    Auth    Security Retry     API Services
 *    API     Headers            │
 *                                 │
 *                  ┌──────────────┼──────────────┐
 *                  ▼              ▼              ▼
 *              Threat API     Scan API       VPN API
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 * This module belongs to the Data layer.
 *
 * The Domain layer must not know:
 *
 * - Retrofit.
 * - OkHttp.
 * - HTTP headers.
 * - Interceptors.
 * - WebSocket implementation.
 * - JSON serialization.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This module only creates dependencies.
 *
 * Business logic must remain outside this class.
 */
@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    // ========================================================================
    // NETWORK CONSTANTS
    // ========================================================================

    /**
     * Base URL for the SentriX backend.
     *
     * IMPORTANT:
     * ------------------------------------------------------------
     * Replace this development URL with the appropriate URL
     * for each build environment.
     *
     * Recommended enterprise setup:
     *
     * debug   -> development API
     * staging -> staging API
     * release -> production API
     *
     * Prefer BuildConfig or environment-specific configuration
     * rather than hard-coding production endpoints.
     */
    private const val BASE_URL =
        "https://api.sentrix.example.com/"

    /**
     * WebSocket endpoint.
     *
     * This is provided separately because WebSocket connections
     * are managed by OkHttp rather than Retrofit.
     */
    private const val WEBSOCKET_URL =
        "wss://api.sentrix.example.com/ws"

    /**
     * HTTP timeout configuration.
     */
    private const val CONNECT_TIMEOUT_SECONDS = 30L
    private const val READ_TIMEOUT_SECONDS = 30L
    private const val WRITE_TIMEOUT_SECONDS = 30L

    /**
     * Media type used by the JSON converter.
     */
    private const val JSON_MEDIA_TYPE =
        "application/json"

    // ========================================================================
    // JSON CONFIGURATION
    // ========================================================================

    /**
     * Provides the Kotlin Serialization Json instance.
     *
     * Configuration:
     *
     * ignoreUnknownKeys
     * -----------------
     * Allows SentriX to safely receive additional fields from
     * newer backend versions without immediately breaking the
     * Android application.
     *
     * isLenient
     * ---------
     * Allows slightly relaxed JSON parsing where appropriate.
     *
     * encodeDefaults
     * --------------
     * Ensures default values can be serialized when required.
     *
     * explicitNulls
     * -------------
     * Keeps null-handling behavior explicit.
     */
    @Provides
    @Singleton
    fun provideJson(): Json {

        return Json {
            ignoreUnknownKeys = true
            isLenient = true
            encodeDefaults = true
            explicitNulls = false
        }
    }

    // ========================================================================
    // INTERCEPTORS
    // ========================================================================

    /**
     * Provides the SentriX authentication interceptor.
     *
     * Responsible for attaching authentication information
     * to protected requests.
     */
    @Provides
    @Singleton
    fun provideAuthInterceptor(): AuthInterceptor {

        return AuthInterceptor()
    }

    /**
     * Provides the SentriX API-key interceptor.
     *
     * Responsible for attaching the API key required by the
     * backend.
     */
    @Provides
    @Singleton
    fun provideApiKeyInterceptor(): ApiKeyInterceptor {

        return ApiKeyInterceptor()
    }

    /**
     * Provides the security-header interceptor.
     *
     * Adds security-related HTTP headers required by SentriX.
     */
    @Provides
    @Singleton
    fun provideSecurityHeaderInterceptor():
        SecurityHeaderInterceptor {

        return SecurityHeaderInterceptor()
    }

    /**
     * Provides the network-status interceptor.
     *
     * Used to expose network availability information to the
     * networking layer.
     */
    @Provides
    @Singleton
    fun provideNetworkStatusInterceptor(
        @ApplicationContext context: Context
    ): NetworkStatusInterceptor {

        return NetworkStatusInterceptor(
            context = context
        )
    }

    /**
     * Provides the retry interceptor.
     *
     * Responsible for controlled retries of appropriate
     * transient network failures.
     */
    @Provides
    @Singleton
    fun provideRetryInterceptor(): RetryInterceptor {

        return RetryInterceptor()
    }

    /**
     * Provides the threat telemetry interceptor.
     *
     * Used by SentriX to capture appropriate security/network
     * telemetry for threat intelligence and diagnostics.
     *
     * IMPORTANT:
     * Sensitive request or response bodies should not be logged
     * unless explicitly required and safely redacted.
     */
    @Provides
    @Singleton
    fun provideThreatTelemetryInterceptor():
        ThreatTelemetryInterceptor {

        return ThreatTelemetryInterceptor()
    }

    /**
     * Provides the application-level logging interceptor.
     *
     * The implementation should already be responsible for
     * redacting sensitive information.
     */
    @Provides
    @Singleton
    fun provideLoggingInterceptor():
        LoggingInterceptor {

        return LoggingInterceptor()
    }

    // ========================================================================
    // OKHTTP CLIENT
    // ========================================================================

    /**
     * Provides the primary OkHttpClient used by Retrofit.
     *
     * Interceptor order is intentional.
     *
     * Application interceptors:
     *
     * 1. Network Status
     * 2. API Key
     * 3. Authentication
     * 4. Security Headers
     * 5. Threat Telemetry
     * 6. Retry
     * 7. Logging
     *
     * The exact behavior of each interceptor should remain
     * inside its own class.
     */
    @Provides
    @Singleton
    fun provideOkHttpClient(
        authInterceptor: AuthInterceptor,
        apiKeyInterceptor: ApiKeyInterceptor,
        securityHeaderInterceptor: SecurityHeaderInterceptor,
        networkStatusInterceptor: NetworkStatusInterceptor,
        retryInterceptor: RetryInterceptor,
        threatTelemetryInterceptor: ThreatTelemetryInterceptor,
        loggingInterceptor: LoggingInterceptor
    ): OkHttpClient {

        return OkHttpClient.Builder()

            // ---------------------------------------------------------------
            // Connection configuration
            // ---------------------------------------------------------------

            .connectTimeout(
                CONNECT_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
            )

            .readTimeout(
                READ_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
            )

            .writeTimeout(
                WRITE_TIMEOUT_SECONDS,
                TimeUnit.SECONDS
            )

            // ---------------------------------------------------------------
            // SentriX interceptors
            // ---------------------------------------------------------------

            .addInterceptor(
                networkStatusInterceptor
            )

            .addInterceptor(
                apiKeyInterceptor
            )

            .addInterceptor(
                authInterceptor
            )

            .addInterceptor(
                securityHeaderInterceptor
            )

            .addInterceptor(
                threatTelemetryInterceptor
            )

            .addInterceptor(
                retryInterceptor
            )

            .addInterceptor(
                loggingInterceptor
            )

            // ---------------------------------------------------------------
            // Security configuration
            // ---------------------------------------------------------------

            /**
             * Follow redirects carefully.
             *
             * Automatic redirects can sometimes hide unexpected
             * endpoint changes. For a security-sensitive product,
             * this should be reviewed together with backend/API
             * requirements.
             */
            .followRedirects(false)

            .followSslRedirects(false)

            .build()
    }

    // ========================================================================
    // RETROFIT
    // ========================================================================

    /**
     * Provides the Retrofit instance used by SentriX API services.
     */
    @Provides
    @Singleton
    fun provideRetrofit(
        okHttpClient: OkHttpClient,
        json: Json
    ): Retrofit {

        val jsonMediaType =
            JSON_MEDIA_TYPE.toMediaType()

        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(
                json.asConverterFactory(
                    jsonMediaType
                )
            )
            .build()
    }

    // ========================================================================
    // API SERVICES
    // ========================================================================

    /**
     * Provides authentication API service.
     */
    @Provides
    @Singleton
    fun provideAuthApiService(
        retrofit: Retrofit
    ): AuthApiService {

        return retrofit.create(
            AuthApiService::class.java
        )
    }

    /**
     * Provides threat API service.
     */
    @Provides
    @Singleton
    fun provideThreatApiService(
        retrofit: Retrofit
    ): ThreatApiService {

        return retrofit.create(
            ThreatApiService::class.java
        )
    }

    /**
     * Provides scan API service.
     */
    @Provides
    @Singleton
    fun provideScanApiService(
        retrofit: Retrofit
    ): ScanApiService {

        return retrofit.create(
            ScanApiService::class.java
        )
    }

    /**
     * Provides security API service.
     */
    @Provides
    @Singleton
    fun provideSecurityApiService(
        retrofit: Retrofit
    ): SecurityApiService {

        return retrofit.create(
            SecurityApiService::class.java
        )
    }

    /**
     * Provides analytics API service.
     */
    @Provides
    @Singleton
    fun provideAnalyticsApiService(
        retrofit: Retrofit
    ): AnalyticsApiService {

        return retrofit.create(
            AnalyticsApiService::class.java
        )
    }

    /**
     * Provides VPN API service.
     */
    @Provides
    @Singleton
    fun provideVPNApiService(
        retrofit: Retrofit
    ): VPNApiService {

        return retrofit.create(
            VPNApiService::class.java
        )
    }

    /**
     * Provides privacy API service.
     */
    @Provides
    @Singleton
    fun providePrivacyApiService(
        retrofit: Retrofit
    ): PrivacyApiService {

        return retrofit.create(
            PrivacyApiService::class.java
        )
    }

    /**
     * Provides security-report API service.
     */
    @Provides
    @Singleton
    fun provideReportApiService(
        retrofit: Retrofit
    ): ReportApiService {

        return retrofit.create(
            ReportApiService::class.java
        )
    }

    /**
     * Provides device-trust API service.
     */
    @Provides
    @Singleton
    fun provideDeviceTrustApiService(
        retrofit: Retrofit
    ): DeviceTrustApiService {

        return retrofit.create(
            DeviceTrustApiService::class.java
        )
    }

    // ========================================================================
    // WEBSOCKET
    // ========================================================================

    /**
     * Provides the SentriX WebSocketManager.
     *
     * WebSocketManager is responsible for:
     *
     * - Opening WebSocket connections.
     * - Managing WebSocket lifecycle.
     * - Reconnecting when appropriate.
     * - Dispatching incoming messages.
     *
     * It should not contain Domain business rules.
     */
    @Provides
    @Singleton
    fun provideWebSocketManager(
        okHttpClient: OkHttpClient
    ): WebSocketManager {

        return WebSocketManager(
            client = okHttpClient,
            webSocketUrl = WEBSOCKET_URL
        )
    }

    // ========================================================================
    // OPTIONAL DEBUG LOGGER
    // ========================================================================

    /**
     * Provides an optional standard OkHttp logging interceptor.
     *
     * This is intentionally separate from SentriX's
     * LoggingInterceptor.
     *
     * DO NOT enable BODY logging in production because API
     * payloads may contain:
     *
     * - Authentication information.
     * - User information.
     * - Security telemetry.
     * - Threat intelligence.
     * - Privacy information.
     *
     * The returned interceptor can be injected into a debug-only
     * network configuration if required.
     */
    @Provides
    @Singleton
    @Named("debugHttpLoggingInterceptor")
    fun provideDebugHttpLoggingInterceptor():
        HttpLoggingInterceptor {

        return HttpLoggingInterceptor().apply {

            level = HttpLoggingInterceptor.Level.BASIC
        }
    }
}
