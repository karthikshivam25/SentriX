package com.sentrix.core.constants

object SecurityConstants {

    /* ============================================================
     * ENCRYPTION ALGORITHMS
     * ============================================================ */

    const val AES = "AES"
    const val RSA = "RSA"
    const val SHA_256 = "SHA-256"
    const val SHA_512 = "SHA-512"

    const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
    const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"

    /* ============================================================
     * KEYSTORE
     * ============================================================ */

    const val ANDROID_KEYSTORE = "AndroidKeyStore"

    const val MASTER_KEY_ALIAS = "SENTRIX_MASTER_KEY"
    const val BIOMETRIC_KEY_ALIAS = "SENTRIX_BIOMETRIC_KEY"

    const val KEY_SIZE_AES = 256
    const val KEY_SIZE_RSA = 2048

    /* ============================================================
     * TOKEN SECURITY
     * ============================================================ */

    const val TOKEN_PREFIX = "Bearer "
    const val TOKEN_EXPIRATION_HOURS = 24L

    const val MIN_PASSWORD_LENGTH = 8
    const val MAX_PASSWORD_LENGTH = 64

    /* ============================================================
     * PASSWORD VALIDATION
     * ============================================================ */

    const val PASSWORD_REGEX =
        "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@#\$%^&+=!]).{8,64}$"

    /* ============================================================
     * SSL / TLS CONFIGURATION
     * ============================================================ */

    const val TLS_VERSION = "TLSv1.3"

    const val CERTIFICATE_TYPE = "X.509"

    const val SSL_PINNING_ENABLED = true

    /* ============================================================
     * ROOT DETECTION
     * ============================================================ */

    const val ROOT_APP_DETECTED = "Root management app detected"
    const val DANGEROUS_APP_DETECTED = "Dangerous application detected"
    const val SU_BINARY_DETECTED = "su binary detected"
    const val TEST_KEYS_DETECTED = "Test keys detected"

    /* ============================================================
     * EMULATOR DETECTION
     * ============================================================ */

    const val EMULATOR_MODEL = "sdk"
    const val EMULATOR_MANUFACTURER = "Genymotion"
    const val EMULATOR_HARDWARE = "goldfish"

    /* ============================================================
     * MALWARE SEVERITY LEVELS
     * ============================================================ */

    const val THREAT_SAFE = 0
    const val THREAT_LOW = 1
    const val THREAT_MEDIUM = 2
    const val THREAT_HIGH = 3
    const val THREAT_CRITICAL = 4

    /* ============================================================
     * MALWARE TYPES
     * ============================================================ */

    const val MALWARE_TROJAN = "Trojan"
    const val MALWARE_SPYWARE = "Spyware"
    const val MALWARE_RANSOMWARE = "Ransomware"
    const val MALWARE_ADWARE = "Adware"
    const val MALWARE_KEYLOGGER = "Keylogger"

    /* ============================================================
     * REALTIME PROTECTION
     * ============================================================ */

    const val REALTIME_MONITORING_INTERVAL = 15_000L
    const val BACKGROUND_SCAN_INTERVAL = 30_000L

    /* ============================================================
     * ANTI-TAMPERING
     * ============================================================ */

    const val APP_SIGNATURE_VALID = "APP_SIGNATURE_VALID"
    const val APP_SIGNATURE_INVALID = "APP_SIGNATURE_INVALID"

    const val DEBUGGER_DETECTED = "Debugger detected"
    const val HOOKING_FRAMEWORK_DETECTED = "Hooking framework detected"

    /* ============================================================
     * DEVICE INTEGRITY
     * ============================================================ */

    const val DEVICE_SECURE = "DEVICE_SECURE"
    const val DEVICE_COMPROMISED = "DEVICE_COMPROMISED"

    /* ============================================================
     * SECURE STORAGE
     * ============================================================ */

    const val ENCRYPTED_PREF_NAME = "sentrix_secure_prefs"

    /* ============================================================
     * BIOMETRIC AUTHENTICATION
     * ============================================================ */

    const val BIOMETRIC_AUTH_TITLE = "SentriX Authentication"
    const val BIOMETRIC_AUTH_SUBTITLE =
        "Verify your identity to continue"

    /* ============================================================
     * NETWORK SECURITY
     * ============================================================ */

    const val MAX_REQUEST_RETRY = 3
    const val REQUEST_RETRY_DELAY = 2000L

    const val NETWORK_ENCRYPTION_REQUIRED = true

    /* ============================================================
     * SECURITY EVENT TYPES
     * ============================================================ */

    const val EVENT_ROOT_DETECTED = "ROOT_DETECTED"
    const val EVENT_TAMPERING_DETECTED = "TAMPERING_DETECTED"
    const val EVENT_MALWARE_FOUND = "MALWARE_FOUND"
    const val EVENT_PHISHING_DETECTED = "PHISHING_DETECTED"

    /* ============================================================
     * FIREBASE / PUSH SECURITY
     * ============================================================ */

    const val FCM_TOKEN_REFRESH = "FCM_TOKEN_REFRESH"

    /* ============================================================
     * SESSION SECURITY
     * ============================================================ */

    const val SESSION_TIMEOUT_MINUTES = 15L
    const val AUTO_LOGOUT_ENABLED = true

}