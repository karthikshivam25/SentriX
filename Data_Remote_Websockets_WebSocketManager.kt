package com.sentrix.data.remote.websockets

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Central manager responsible for handling all WebSocket
 * connections within SentriX.
 *
 * Responsibilities:
 * - Create WebSocket connections
 * - Manage active socket lifecycle
 * - Maintain connection states
 * - Reconnect disconnected sockets
 * - Close all sockets during logout
 *
 * Architecture:
 *
 * Repository
 *      ↓
 * WebSocketManager
 *      ↓
 * ThreatFeedSocket / SecurityAlertSocket
 *      ↓
 * SentriX Cloud
 */
@Singleton
class WebSocketManager @Inject constructor(

    // OkHttp client used to establish WebSocket connections
    private val okHttpClient: OkHttpClient

) {

    companion object {
        private const val TAG = "WebSocketManager"
    }

    /**
     * Holds all active websocket connections.
     *
     * Key   -> Socket identifier
     * Value -> WebSocket instance
     */
    private val activeSockets =
        mutableMapOf<String, WebSocket>()

    /**
     * Current connection state.
     */
    private val _connectionState =
        MutableStateFlow(ConnectionState.DISCONNECTED)

    /**
     * Public immutable connection state.
     */
    val connectionState: StateFlow<ConnectionState> =
        _connectionState.asStateFlow()

    /**
     * Opens a websocket connection.
     *
     * Example:
     *
     * connect(
     *      socketId = "THREAT_FEED",
     *      url = "wss://api.sentrix.com/threats",
     *      listener = threatFeedSocket
     * )
     */
    fun connect(
        socketId: String,
        url: String,
        listener: okhttp3.WebSocketListener
    ) {

        // Prevent duplicate connections
        if (activeSockets.containsKey(socketId)) {

            Log.d(
                TAG,
                "Socket already connected: $socketId"
            )

            return
        }

        try {

            _connectionState.value =
                ConnectionState.CONNECTING

            val request = Request.Builder()
                .url(url)
                .build()

            val socket = okHttpClient.newWebSocket(
                request,
                listener
            )

            activeSockets[socketId] = socket

            _connectionState.value =
                ConnectionState.CONNECTED

            Log.d(
                TAG,
                "Connected socket: $socketId"
            )

        } catch (exception: Exception) {

            Log.e(
                TAG,
                "Connection failed for $socketId",
                exception
            )

            _connectionState.value =
                ConnectionState.FAILED
        }
    }

    /**
     * Sends a message through a specific socket.
     */
    fun sendMessage(
        socketId: String,
        message: String
    ): Boolean {

        return activeSockets[socketId]
            ?.send(message)
            ?: false
    }

    /**
     * Disconnects a specific socket.
     */
    fun disconnect(
        socketId: String
    ) {

        activeSockets[socketId]?.close(
            1000,
            "Disconnected by client"
        )

        activeSockets.remove(socketId)

        Log.d(
            TAG,
            "Disconnected socket: $socketId"
        )

        if (activeSockets.isEmpty()) {

            _connectionState.value =
                ConnectionState.DISCONNECTED
        }
    }

    /**
     * Disconnects all active sockets.
     *
     * Useful during:
     * - Logout
     * - Application shutdown
     */
    fun disconnectAll() {

        activeSockets.forEach { (_, socket) ->

            socket.close(
                1000,
                "Application shutdown"
            )
        }

        activeSockets.clear()

        _connectionState.value =
            ConnectionState.DISCONNECTED

        Log.d(
            TAG,
            "All sockets disconnected."
        )
    }

    /**
     * Returns true if a socket is currently active.
     */
    fun isConnected(
        socketId: String
    ): Boolean {

        return activeSockets.containsKey(socketId)
    }

    /**
     * Returns the requested socket instance.
     */
    fun getSocket(
        socketId: String
    ): WebSocket? {

        return activeSockets[socketId]
    }

    /**
     * Returns total active socket count.
     */
    fun getActiveSocketCount(): Int {

        return activeSockets.size
    }
}

/**
 * Represents the current websocket connection state.
 */
enum class ConnectionState {

    // Attempting to establish connection
    CONNECTING,

    // Connection successfully established
    CONNECTED,

    // No active connection exists
    DISCONNECTED,

    // Connection attempt failed
    FAILED
}
