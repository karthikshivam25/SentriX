package com.sentrix.data.remote.websockets

import android.util.Log
import com.sentrix.data.remote.dto.SecurityAlertDto
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import javax.inject.Inject
import javax.inject.Singleton

/**
 * WebSocket listener responsible for receiving
 * real-time security alerts from the SentriX backend.
 *
 * Examples of alerts:
 * - Malware detected
 * - Phishing URL blocked
 * - Suspicious network activity
 * - Device integrity compromised
 * - Privacy risk detected
 *
 * Architecture:
 *
 * Backend
 *    ↓
 * WebSocket
 *    ↓
 * SecurityAlertSocket
 *    ↓
 * Repository
 *    ↓
 * ViewModel
 *    ↓
 * UI Notification / Dashboard
 */
@Singleton
class SecurityAlertSocket @Inject constructor(

    // JSON parser used to deserialize incoming alerts
    private val json: Json

) : WebSocketListener() {

    companion object {
        private const val TAG = "SecurityAlertSocket"
    }

    /**
     * Internal flow containing security alerts.
     *
     * replay = 1 ensures newly subscribed collectors
     * immediately receive the latest alert.
     */
    private val _securityAlerts =
        MutableSharedFlow<SecurityAlertDto>(
            replay = 1,
            extraBufferCapacity = 20
        )

    /**
     * Public immutable flow exposed to the application.
     */
    val securityAlerts: SharedFlow<SecurityAlertDto> =
        _securityAlerts.asSharedFlow()

    /**
     * Called when websocket connection opens successfully.
     */
    override fun onOpen(
        webSocket: WebSocket,
        response: Response
    ) {
        super.onOpen(webSocket, response)

        Log.d(TAG, "Security alert stream connected.")

        // Subscribe to security alerts
        subscribe(webSocket)
    }

    /**
     * Called whenever a new message arrives.
     *
     * Expected JSON:
     * {
     *   "alert_id":"ALT_001",
     *   "title":"Malware Detected",
     *   "severity":"CRITICAL"
     * }
     */
    override fun onMessage(
        webSocket: WebSocket,
        text: String
    ) {
        super.onMessage(webSocket, text)

        Log.d(TAG, "Alert received: $text")

        try {

            // Deserialize JSON response
            val alert =
                json.decodeFromString<SecurityAlertDto>(text)

            // Emit alert to collectors
            _securityAlerts.tryEmit(alert)

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Unable to parse security alert.",
                exception
            )
        }
    }

    /**
     * Called when server starts closing connection.
     */
    override fun onClosing(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosing(webSocket, code, reason)

        Log.d(
            TAG,
            "Socket closing: $reason"
        )

        webSocket.close(code, reason)
    }

    /**
     * Called after socket is completely closed.
     */
    override fun onClosed(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosed(webSocket, code, reason)

        Log.d(
            TAG,
            "Socket closed: $reason"
        )
    }

    /**
     * Called whenever websocket encounters an error.
     */
    override fun onFailure(
        webSocket: WebSocket,
        t: Throwable,
        response: Response?
    ) {
        super.onFailure(webSocket, t, response)

        Log.e(
            TAG,
            "Security alert socket failure.",
            t
        )

        // Optional:
        // Implement automatic reconnection here.
    }

    /**
     * Subscribes to security alerts.
     */
    private fun subscribe(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"SUBSCRIBE_SECURITY_ALERTS",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }

    /**
     * Unsubscribes from security alerts.
     */
    fun unsubscribe(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"UNSUBSCRIBE_SECURITY_ALERTS"
            }
            """.trimIndent()
        )
    }

    /**
     * Sends heartbeat messages to keep
     * the connection alive.
     */
    fun sendHeartbeat(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"PING",
                "channel":"SECURITY_ALERTS",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }
}
