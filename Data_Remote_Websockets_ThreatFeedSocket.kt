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
 * WebSocket listener responsible for receiving
 * live threat intelligence feeds from the SentriX Cloud.
 *
 * Threat feeds may include:
 * - Newly discovered malware signatures
 * - Phishing URLs
 * - Scam domains
 * - Malicious IP addresses
 * - Zero-day threat alerts
 * - Threat intelligence updates
 *
 * Architecture:
 *
 * SentriX Cloud
 *        ↓
 * WebSocket
 *        ↓
 * ThreatFeedSocket
 *        ↓
 * Repository
 *        ↓
 * Local Database
 *        ↓
 * Protection Engine
 */
@Singleton
class ThreatFeedSocket @Inject constructor(

    // JSON parser used to deserialize incoming threat feeds
    private val json: Json

) : WebSocketListener() {

    companion object {
        private const val TAG = "ThreatFeedSocket"
    }

    /**
     * Internal flow used to emit incoming threat feed updates.
     *
     * replay = 1 ensures new collectors immediately receive
     * the latest threat feed event.
     */
    private val _threatFeeds =
        MutableSharedFlow<ThreatDto>(
            replay = 1,
            extraBufferCapacity = 50
        )

    /**
     * Public immutable flow exposed to repositories/viewmodels.
     */
    val threatFeeds: SharedFlow<ThreatDto> =
        _threatFeeds.asSharedFlow()

    /**
     * Called when the WebSocket connection is successfully established.
     */
    override fun onOpen(
        webSocket: WebSocket,
        response: Response
    ) {
        super.onOpen(webSocket, response)

        Log.d(TAG, "Connected to SentriX Threat Feed.")

        // Subscribe to threat intelligence feed
        subscribe(webSocket)
    }

    /**
     * Called whenever a threat feed update arrives.
     *
     * Expected JSON:
     *
     * {
     *   "threat_id":"THR_001",
     *   "name":"Android.Banker.XYZ",
     *   "severity":"CRITICAL"
     * }
     */
    override fun onMessage(
        webSocket: WebSocket,
        text: String
    ) {
        super.onMessage(webSocket, text)

        Log.d(TAG, "Threat feed received: $text")

        try {

            // Convert JSON payload into ThreatDto
            val threatFeed =
                json.decodeFromString<ThreatDto>(text)

            // Emit feed to subscribers
            _threatFeeds.tryEmit(threatFeed)

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Failed to parse threat feed.",
                exception
            )
        }
    }

    /**
     * Called when the server initiates connection closing.
     */
    override fun onClosing(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosing(webSocket, code, reason)

        Log.d(
            TAG,
            "Threat feed closing: $reason"
        )

        webSocket.close(code, reason)
    }

    /**
     * Called when the WebSocket connection is fully closed.
     */
    override fun onClosed(
        webSocket: WebSocket,
        code: Int,
        reason: String
    ) {
        super.onClosed(webSocket, code, reason)

        Log.d(
            TAG,
            "Threat feed closed: $reason"
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
            "Threat feed socket failure.",
            t
        )

        // Optional:
        // Trigger automatic reconnection here.
    }

    /**
     * Subscribes to the cloud threat feed channel.
     */
    private fun subscribe(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"SUBSCRIBE_THREAT_FEED",
                "client":"SentriX_Android",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }

    /**
     * Unsubscribes from the threat feed.
     */
    fun unsubscribe(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"UNSUBSCRIBE_THREAT_FEED"
            }
            """.trimIndent()
        )
    }

    /**
     * Sends a heartbeat to keep the connection alive.
     */
    fun sendHeartbeat(
        webSocket: WebSocket
    ) {

        webSocket.send(
            """
            {
                "event":"PING",
                "channel":"THREAT_FEED",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }
}
