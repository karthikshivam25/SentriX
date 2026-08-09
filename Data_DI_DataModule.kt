package com.sentrix.data.di

import android.content.Context
import com.sentrix.data.local.preferences.ThemePreferences
import com.sentrix.data.remote.websockets.RealtimeThreatListener
import com.sentrix.data.remote.websockets.SecurityAlertSocket
import com.sentrix.data.remote.websockets.ThreatFeedSocket
import com.sentrix.data.remote.websockets.WebSocketManager
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

/**
 * SentriX - Data Layer Dependency Injection Module
 *
 * Package:
 * com.sentrix.data.di
 *
 * Responsibility
 * ------------------------------------------------------------
 * Provides shared Data-layer dependencies that do not belong
 * exclusively to:
 *
 * - DatabaseModule
 * - NetworkModule
 * - CacheModule
 * - RepositoryModule
 *
 * This module acts as the central Data-layer wiring point for
 * supporting infrastructure such as:
 *
 * - Data preferences.
 * - WebSocket listeners.
 * - Real-time security event handlers.
 * - Shared Data-layer coordinators.
 *
 * Clean Architecture:
 * ------------------------------------------------------------
 *
 * Presentation
 *       │
 *       ▼
 * Domain / UseCases
 *       │
 *       ▼
 * Repository Interfaces
 *       │
 *       ▼
 * Data Layer
 *       │
 * ┌─────┼──────────┬──────────┐
 * ▼     ▼          ▼          ▼
 * API   Room      Cache    Preferences
 *
 * DataModule belongs entirely to the Data layer.
 *
 * IMPORTANT:
 * ------------------------------------------------------------
 * This module must not contain:
 *
 * - Business rules.
 * - Threat scoring.
 * - Malware analysis.
 * - Privacy decisions.
 * - Repository implementations.
 * - Database creation.
 * - Retrofit creation.
 *
 * Those responsibilities belong to the appropriate modules.
 */
@Module
@InstallIn(SingletonComponent::class)
object DataModule {

    // ========================================================================
    // THEME PREFERENCES
    // ========================================================================

    /**
     * Provides ThemePreferences.
     *
     * ThemePreferences belongs to the Data/Preferences layer
     * and is responsible for persisting application theme
     * preferences.
     *
     * Application context is used so that the preferences
     * object does not accidentally retain an Activity context.
     */
    @Provides
    @Singleton
    fun provideThemePreferences(
        @ApplicationContext context: Context
    ): ThemePreferences {

        return ThemePreferences(
            context = context
        )
    }

    // ========================================================================
    // REAL-TIME THREAT LISTENER
    // ========================================================================

    /**
     * Provides the RealtimeThreatListener.
     *
     * This component receives real-time threat information
     * from the WebSocket layer.
     *
     * It should remain focused on translating incoming
     * real-time events into application-level events.
     *
     * Threat analysis itself belongs to the Domain layer.
     */
    @Provides
    @Singleton
    fun provideRealtimeThreatListener():
        RealtimeThreatListener {

        return RealtimeThreatListener()
    }

    // ========================================================================
    // SECURITY ALERT SOCKET
    // ========================================================================

    /**
     * Provides the SecurityAlertSocket.
     *
     * SecurityAlertSocket is responsible for receiving
     * real-time security-alert events.
     *
     * WebSocket lifecycle management remains the responsibility
     * of WebSocketManager.
     */
    @Provides
    @Singleton
    fun provideSecurityAlertSocket(
        webSocketManager: WebSocketManager
    ): SecurityAlertSocket {

        return SecurityAlertSocket(
            webSocketManager = webSocketManager
        )
    }

    // ========================================================================
    // THREAT FEED SOCKET
    // ========================================================================

    /**
     * Provides the ThreatFeedSocket.
     *
     * Responsible for consuming the SentriX real-time
     * threat-intelligence feed.
     */
    @Provides
    @Singleton
    fun provideThreatFeedSocket(
        webSocketManager: WebSocketManager
    ): ThreatFeedSocket {

        return ThreatFeedSocket(
            webSocketManager = webSocketManager
        )
    }

    // ========================================================================
    // DATA-LAYER VALIDATION
    // ========================================================================

    /**
     * Data-layer dependency configuration should remain
     * intentionally lightweight.
     *
     * Domain validators and security rules should NOT be
     * constructed here.
     *
     * Examples that belong elsewhere:
     *
     * EmailValidator
     * PasswordValidator
     * ThreatSeverityRules
     * RiskScoringRules
     * PrivacyRules
     *
     * Keeping these outside DataModule prevents the Data layer
     * from becoming coupled to Domain business logic.
     */

    // ========================================================================
    // DATA MODULE DESIGN NOTES
    // ========================================================================

    /**
     * The following dependencies intentionally belong to
     * separate DI modules:
     *
     * DatabaseModule
     * ----------------
     * SentriXDatabase
     * DAOs
     *
     * NetworkModule
     * ----------------
     * Json
     * OkHttpClient
     * Retrofit
     * API services
     * WebSocketManager
     *
     * CacheModule
     * ----------------
     * MemoryCache
     * ThreatCache
     * ScanCache
     * VPNCache
     * UserCache
     * SecurityMetricsCache
     * SecurityReportCache
     * ThreatHistoryCache
     * CacheManager
     *
     * RepositoryModule
     * ----------------
     * Domain repository interface -> implementation bindings
     *
     * DataModule
     * ----------------
     * Shared Data-layer utilities and real-time components.
     */
}
