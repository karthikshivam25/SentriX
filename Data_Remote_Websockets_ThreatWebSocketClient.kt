package com.sentrix.data.remote.websockets

import android.util.Log
import com.sentrix.data.remote.dto.ThreatDto
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import javax.inject.Inject
import javax.inject.Singleton

/**
 * WebSocket client responsible for receiving real-time threat updates
 * from the SentriX backend.
 *
 * Features:
 * - Real-time threat monitoring
 * - Automatic reconnection support (can be extended)
 * - Flow-based reactive stream
 * - Clean Architecture friendly
 *
 * Example WebSocket URL:
 * wss://api.sentrix.com/ws/threats
 */
@Singleton
class ThreatWebSocketClient @Inject constructor(

    // OkHttp client injected through Hilt/Dagger
    private val okHttpClient: OkHttpClient,

    // JSON parser used to deserialize incoming messages
    private val json: Json

) {

    companion object {
        private const val TAG = "ThreatWebSocket"
    }

    // Background scope used for websocket operations
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO
    )

    // Reference to active websocket connection
    private var webSocket: WebSocket? = null

    /**
     * Opens a websocket connection and emits ThreatDto objects
     * whenever the backend sends a new threat event.
     *
     * Usage:
     *
     * threatWebSocketClient.connect(url)
     *      .collect { threat ->
     *          // Update UI / Database
     *      }
     */
    fun connect(webSocketUrl: String): Flow<ThreatDto> = callbackFlow {

        val request = Request.Builder()
            .url(webSocketUrl)
            .build()

        webSocket = okHttpClient.newWebSocket(
            request,
            object : WebSocketListener() {

                /**
                 * Called when connection is successfully established.
                 */
                override fun onOpen(
                    webSocket: WebSocket,
                    response: Response
                ) {
                    super.onOpen(webSocket, response)

                    Log.d(TAG, "WebSocket connected.")
                }

                /**
                 * Called whenever a message is received from server.
                 *
                 * Expected JSON:
                 * {
                 *   "id":"123",
                 *   "name":"Banking Trojan"
                 * }
                 */
                override fun onMessage(
                    webSocket: WebSocket,
                    text: String
                ) {
                    super.onMessage(webSocket, text)

                    Log.d(TAG, "Message received: $text")

                    scope.launch {
                        try {

                            // Convert incoming JSON into ThreatDto
                            val threat =
                                json.decodeFromString<ThreatDto>(text)

                            // Emit threat to collectors
                            trySend(threat)

                        } catch (exception: Exception) {

                            Log.e(
                                TAG,
                                "Failed to parse threat message",
                                exception
                            )
                        }
                    }
                }

                /**
                 * Called when websocket starts closing.
                 */
                override fun onClosing(
                    webSocket: WebSocket,
                    code: Int,
                    reason: String
                ) {
                    super.onClosing(webSocket, code, reason)

                    Log.d(
                        TAG,
                        "WebSocket closing: $reason"
                    )

                    webSocket.close(code, reason)
                }

                /**
                 * Called after websocket has been closed.
                 */
                override fun onClosed(
                    webSocket: WebSocket,
                    code: Int,
                    reason: String
                ) {
                    super.onClosed(webSocket, code, reason)

                    Log.d(
                        TAG,
                        "WebSocket closed: $reason"
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
                        "WebSocket failure",
                        t
                    )

                    close(t)
                }
            }
        )

        /**
         * Executed when Flow collector is cancelled.
         */
        awaitClose {
            disconnect()
        }
    }

    /**
     * Sends a raw text message to the websocket server.
     *
     * Example:
     * sendMessage("{\"action\":\"PING\"}")
     */
    fun sendMessage(message: String) {
        webSocket?.send(message)
    }

    /**
     * Gracefully disconnects websocket connection.
     */
    fun disconnect() {

        webSocket?.close(
            1000,
            "Client disconnected"
        )

        webSocket = null

        Log.d(TAG, "WebSocket disconnected.")
    }

    /**
     * Sends heartbeat/ping message to backend.
     * Useful to keep connection alive.
     */
    fun sendHeartbeat() {

        sendMessage(
            """
            {
                "type":"PING",
                "timestamp":${System.currentTimeMillis()}
            }
            """.trimIndent()
        )
    }
}
