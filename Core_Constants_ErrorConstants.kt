package com.sentrix.core.constants

object ErrorConstants {

    /* ============================================================
     * GENERAL ERRORS
     * ============================================================ */

    const val UNKNOWN_ERROR =
        "Unknown error occurred"

    const val SOMETHING_WENT_WRONG =
        "Something went wrong"

    const val INVALID_REQUEST =
        "Invalid request"

    const val OPERATION_FAILED =
        "Operation failed"

    /* ============================================================
     * NETWORK ERRORS
     * ============================================================ */

    const val NO_INTERNET_CONNECTION =
        "No internet connection"

    const val NETWORK_TIMEOUT =
        "Network timeout"

    const val SERVER_UNREACHABLE =
        "Server unreachable"

    const val API_ERROR =
        "API request failed"

    const val SSL_HANDSHAKE_FAILED =
        "SSL handshake failed"

    /* ============================================================
     * AUTHENTICATION ERRORS
     * ============================================================ */

    const val INVALID_CREDENTIALS =
        "Invalid credentials"

    const val SESSION_EXPIRED =
        "Session expired"

    const val ACCESS_DENIED =
        "Access denied"

    const val TOKEN_EXPIRED =
        "Authentication token expired"

    const val BIOMETRIC_AUTH_FAILED =
        "Biometric authentication failed"

    /* ============================================================
     * VALIDATION ERRORS
     * ============================================================ */

    const val INVALID_EMAIL =
        "Invalid email address"

    const val INVALID_PASSWORD =
        "Invalid password"

    const val INVALID_PHONE_NUMBER =
        "Invalid phone number"

    const val REQUIRED_FIELD_MISSING =
        "Required field missing"

    const val INVALID_INPUT =
        "Invalid input"

    /* ============================================================
     * DATABASE ERRORS
     * ============================================================ */

    const val DATABASE_ERROR =
        "Database operation failed"

    const val DATA_NOT_FOUND =
        "Data not found"

    const val INSERT_FAILED =
        "Insert operation failed"

    const val UPDATE_FAILED =
        "Update operation failed"

    const val DELETE_FAILED =
        "Delete operation failed"

    /* ============================================================
     * SECURITY ERRORS
     * ============================================================ */

    const val ROOT_DETECTED =
        "Rooted device detected"

    const val TAMPERING_DETECTED =
        "Application tampering detected"

    const val MALWARE_DETECTED =
        "Malware threat detected"

    const val PHISHING_DETECTED =
        "Phishing attack detected"

    const val ENCRYPTION_FAILED =
        "Encryption failed"

    const val DECRYPTION_FAILED =
        "Decryption failed"

    /* ============================================================
     * FILE ERRORS
     * ============================================================ */

    const val FILE_NOT_FOUND =
        "File not found"

    const val FILE_READ_FAILED =
        "File read failed"

    const val FILE_WRITE_FAILED =
        "File write failed"

    const val FILE_UPLOAD_FAILED =
        "File upload failed"

    const val INVALID_FILE_FORMAT =
        "Invalid file format"

    /* ============================================================
     * SCAN ERRORS
     * ============================================================ */

    const val SCAN_FAILED =
        "Security scan failed"

    const val SCAN_INTERRUPTED =
        "Scan interrupted"

    const val UNSUPPORTED_SCAN_TYPE =
        "Unsupported scan type"

    /* ============================================================
     * CACHE ERRORS
     * ============================================================ */

    const val CACHE_ERROR =
        "Cache operation failed"

    const val CACHE_NOT_FOUND =
        "Cache data not found"

    const val CACHE_EXPIRED =
        "Cache expired"

    /* ============================================================
     * PERMISSION ERRORS
     * ============================================================ */

    const val PERMISSION_DENIED =
        "Permission denied"

    const val STORAGE_PERMISSION_REQUIRED =
        "Storage permission required"

    const val LOCATION_PERMISSION_REQUIRED =
        "Location permission required"

    const val CAMERA_PERMISSION_REQUIRED =
        "Camera permission required"

    /* ============================================================
     * HTTP ERROR CODES
     * ============================================================ */

    const val ERROR_400 =
        "Bad request"

    const val ERROR_401 =
        "Unauthorized"

    const val ERROR_403 =
        "Forbidden"

    const val ERROR_404 =
        "Resource not found"

    const val ERROR_500 =
        "Internal server error"

    /* ============================================================
     * ERROR TAGS
     * ============================================================ */

    const val TAG_NETWORK_ERROR =
        "NETWORK_ERROR"

    const val TAG_DATABASE_ERROR =
        "DATABASE_ERROR"

    const val TAG_SECURITY_ERROR =
        "SECURITY_ERROR"

    const val TAG_VALIDATION_ERROR =
        "VALIDATION_ERROR"

}
