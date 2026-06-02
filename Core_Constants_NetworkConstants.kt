package com.sentrix.core.constants

object NetworkConstants {

    /* ============================================================
     * NETWORK TIMEOUTS
     * ============================================================ */

    const val CONNECT_TIMEOUT = 30L
    const val READ_TIMEOUT = 30L
    const val WRITE_TIMEOUT = 30L

    const val PING_INTERVAL = 15L

    /* ============================================================
     * RETRY CONFIGURATION
     * ============================================================ */

    const val MAX_RETRY_COUNT = 3
    const val RETRY_DELAY = 2000L

    /* ============================================================
     * CACHE CONFIGURATION
     * ============================================================ */

    const val CACHE_SIZE = 10L * 1024L * 1024L // 10 MB
    const val CACHE_MAX_AGE = 60 * 60 // 1 hour
    const val CACHE_MAX_STALE = 60 * 60 * 24 * 7 // 7 days

    /* ============================================================
     * CONTENT TYPES
     * ============================================================ */

    const val CONTENT_TYPE_JSON = "application/json"
    const val CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
    const val CONTENT_TYPE_MULTIPART = "multipart/form-data"

    /* ============================================================
     * REQUEST HEADERS
     * ============================================================ */

    const val HEADER_AUTHORIZATION = "Authorization"
    const val HEADER_ACCEPT = "Accept"
    const val HEADER_CONTENT_TYPE = "Content-Type"
    const val HEADER_USER_AGENT = "User-Agent"
    const val HEADER_DEVICE_ID = "Device-Id"
    const val HEADER_PLATFORM = "Platform"

    /* ============================================================
     * HEADER VALUES
     * ============================================================ */

    const val PLATFORM_ANDROID = "Android"

    const val USER_AGENT =
        "SentriX-Mobile-Security/1.0"

    /* ============================================================
     * HTTP STATUS CODES
     * ============================================================ */

    const val HTTP_OK = 200
    const val HTTP_CREATED = 201
    const val HTTP_ACCEPTED = 202

    const val HTTP_BAD_REQUEST = 400
    const val HTTP_UNAUTHORIZED = 401
    const val HTTP_FORBIDDEN = 403
    const val HTTP_NOT_FOUND = 404
    const val HTTP_CONFLICT = 409

    const val HTTP_SERVER_ERROR = 500
    const val HTTP_BAD_GATEWAY = 502
    const val HTTP_SERVICE_UNAVAILABLE = 503

    /* ============================================================
     * API RATE LIMITING
     * ============================================================ */

    const val MAX_REQUESTS_PER_MINUTE = 120
    const val RATE_LIMIT_WINDOW = 60_000L

    /* ============================================================
     * SSL / TLS SETTINGS
     * ============================================================ */

    const val TLS_VERSION = "TLSv1.3"

    const val SSL_PINNING_ENABLED = true
    const val CERTIFICATE_TYPE = "X.509"

    /* ============================================================
     * WEBSOCKET CONFIGURATION
     * ============================================================ */

    const val SOCKET_CONNECT_TIMEOUT = 20L
    const val SOCKET_RECONNECT_INTERVAL = 5000L

    const val SOCKET_EVENT_THREAT = "THREAT_EVENT"
    const val SOCKET_EVENT_SCAN = "SCAN_EVENT"
    const val SOCKET_EVENT_ALERT = "ALERT_EVENT"

    /* ============================================================
     * DOWNLOAD CONFIGURATION
     * ============================================================ */

    const val MAX_DOWNLOAD_SIZE = 100 * 1024 * 1024 // 100 MB

    const val DOWNLOAD_BUFFER_SIZE = 8192

    /* ============================================================
     * UPLOAD CONFIGURATION
     * ============================================================ */

    const val MAX_UPLOAD_SIZE = 50 * 1024 * 1024 // 50 MB

    /* ============================================================
     * NETWORK SECURITY FLAGS
     * ============================================================ */

    const val ALLOW_HTTP = false
    const val ENFORCE_HTTPS = true

    const val VERIFY_HOSTNAME = true

    /* ============================================================
     * API RESPONSE KEYS
     * ============================================================ */

    const val RESPONSE_SUCCESS = "success"
    const val RESPONSE_MESSAGE = "message"
    const val RESPONSE_DATA = "data"
    const val RESPONSE_ERROR = "error"

    /* ============================================================
     * CONNECTION STATES
     * ============================================================ */

    const val STATE_CONNECTED = "CONNECTED"
    const val STATE_DISCONNECTED = "DISCONNECTED"
    const val STATE_CONNECTING = "CONNECTING"
    const val STATE_RECONNECTING = "RECONNECTING"

    /* ============================================================
     * NETWORK TYPES
     * ============================================================ */

    const val NETWORK_WIFI = "WIFI"
    const val NETWORK_MOBILE = "MOBILE"
    const val NETWORK_ETHERNET = "ETHERNET"
    const val NETWORK_UNKNOWN = "UNKNOWN"

    /* ============================================================
     * INTERCEPTOR TAGS
     * ============================================================ */

    const val INTERCEPTOR_AUTH = "AUTH_INTERCEPTOR"
    const val INTERCEPTOR_LOGGING = "LOGGING_INTERCEPTOR"
    const val INTERCEPTOR_SECURITY = "SECURITY_INTERCEPTOR"

    /* ============================================================
     * LOGGING
     * ============================================================ */

    const val NETWORK_LOG_TAG = "SENTRIX_NETWORK"

}