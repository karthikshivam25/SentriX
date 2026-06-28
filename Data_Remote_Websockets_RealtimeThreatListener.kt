package com.sentrix.data.remote.websockets

import android.util.Log
import com.sentrix.data.remote.dto.ThreatDto
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
 * WebSocket listener responsible for handling
 * real-time threat events received from the SentriX backend.
 *
 * This class listens for:
 * - Newly detected threats
 * - Threat updates
 * - Threat removals
 * - Emergency security alerts
 *
 * Architecture:
 * WebSocket -> Listener -> SharedFlow -> Repository -> ViewModel -> UI
 */
@Singleton
class RealtimeThreatListener @Inject constructor(

    // JSON parser used to deserialize threat messages
    private val json: Json

) : WebSocketListener() {

    companion object {
        private const val TAG = "RealtimeThreatListener"
    }

    /**
     * Internal flow used to emit threat events.
     *
     * replay = 1 ensures newly subscribed collectors
     * receive the latest threat event.
     */
    private val _threatEvents =
        MutableSharedFlow<ThreatDto>(
            replay = 1,
            extraBufferCapacity = 10
        )

    /**
     * Public immutable flow exposed to the application.
     */
    val threatEvents: SharedFlow<ThreatDto> =
        _threatEvents.asSharedFlow()

    /**
     * Called when WebSocket connection is established.
     */
    override fun onOpen(
        webSocket: WebSocket,
        response: Response
    ) {
        super.onOpen(webSocket, response)

        Log.d(TAG, "Connected to threat stream.")

        // Notify backend that client is ready
        webSocket.send(
            """
            {
                "event":"SUBSCRIBE_THREATS",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }

    /**
     * Called whenever a text message is received.
     *
     * Expected JSON Example:
     *
     * {
     *   "threat_id":"THR_001",
     *   "threat_name":"Banking Trojan",
     *   "severity":"CRITICAL"
     * }
     */
    override fun onMessage(
        webSocket: WebSocket,
        text: String
    ) {
        super.onMessage(webSocket, text)

        Log.d(TAG, "Threat event received: $text")

        try {

            // Convert JSON into ThreatDto
            val threat =
                json.decodeFromString<ThreatDto>(text)

            // Emit event to application
            _threatEvents.tryEmit(threat)

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Failed to parse threat event",
                exception
            )
        }
    }

    /**
     * Called when server initiates connection closing.
     */
    override fun onClosing(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosing(webSocket, code, reason)

        Log.d(
            TAG,
            "Connection closing. Code: $code Reason: $reason"
        )

        // Gracefully close the socket
        webSocket.close(code, reason)
    }

    /**
     * Called after connection is completely closed.
     */
    override fun onClosed(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosed(webSocket, code, reason)

        Log.d(
            TAG,
            "Connection closed. Code: $code Reason: $reason"
        )
    }

    /**
     * Called whenever the WebSocket encounters an error.
     */
    override fun onFailure(
        webSocket: WebSocket,
        t: Throwable,
        response: Response?
    ) {
        super.onFailure(webSocket, t, response)

        Log.e(
            TAG,
            "Realtime threat listener failed",
            t
        )

        // Optional:
        // Trigger reconnection logic here.
    }

    /**
     * Sends heartbeat ping messages to keep the
     * WebSocket connection alive.
     */
    fun sendHeartbeat(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"PING",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }

    /**
     * Sends an unsubscribe event before disconnecting.
     */
    fun unsubscribe(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"UNSUBSCRIBE_THREATS"
            }
            """.trimIndent()
        )
    }
}
