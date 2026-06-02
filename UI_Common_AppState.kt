package com.sentrix.ui.common

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

object AppState {

    // ----------------------------------------------------------------
    // AUTHENTICATION
    // ----------------------------------------------------------------

    var isUserLoggedIn by mutableStateOf(false)

    var currentUsername by mutableStateOf("SentriX User")

    var currentUserEmail by mutableStateOf(
        "user@sentrix.ai"
    )

    // ----------------------------------------------------------------
    // SECURITY STATUS
    // ----------------------------------------------------------------

    var securityScore by mutableStateOf(92)

    var activeThreats by mutableStateOf(0)

    var blockedThreats by mutableStateOf(24)

    var realtimeProtectionEnabled by mutableStateOf(true)

    var firewallEnabled by mutableStateOf(true)

    var privacyShieldEnabled by mutableStateOf(true)

    // ----------------------------------------------------------------
    // DEVICE STATUS
    // ----------------------------------------------------------------

    var deviceConnected by mutableStateOf(true)

    var cloudSyncEnabled by mutableStateOf(false)

    var networkProtected by mutableStateOf(true)

    var deviceScanning by mutableStateOf(false)

    // ----------------------------------------------------------------
    // SETTINGS
    // ----------------------------------------------------------------

    var darkModeEnabled by mutableStateOf(true)

    var notificationsEnabled by mutableStateOf(true)

    var biometricEnabled by mutableStateOf(true)

    var analyticsEnabled by mutableStateOf(false)

    // ----------------------------------------------------------------
    // SUBSCRIPTION
    // ----------------------------------------------------------------

    var currentPlan by mutableStateOf(
        UIConstants.PLAN_PRO
    )

    var subscriptionActive by mutableStateOf(true)

    // ----------------------------------------------------------------
    // SCAN INFORMATION
    // ----------------------------------------------------------------

    var lastScanTime by mutableStateOf(
        "2 mins ago"
    )

    var scanProgress by mutableStateOf(0f)

    var scannedFilesCount by mutableStateOf(0)

    // ----------------------------------------------------------------
    // NETWORK MONITORING
    // ----------------------------------------------------------------

    var uploadSpeed by mutableStateOf(0f)

    var downloadSpeed by mutableStateOf(0f)

    var suspiciousConnections by mutableStateOf(0)

    // ----------------------------------------------------------------
    // UI STATE
    // ----------------------------------------------------------------

    var showLoadingScreen by mutableStateOf(false)

    var showSecurityAlert by mutableStateOf(false)

    var selectedBottomNavIndex by mutableStateOf(0)

    // ----------------------------------------------------------------
    // METHODS
    // ----------------------------------------------------------------

    fun resetSecurityState() {

        activeThreats = 0

        blockedThreats = 0

        securityScore = 100

        realtimeProtectionEnabled = true

        firewallEnabled = true

        privacyShieldEnabled = true
    }

    fun startScan() {

        deviceScanning = true

        scanProgress = 0f

        scannedFilesCount = 0
    }

    fun completeScan(
        threatsFound: Int
    ) {

        deviceScanning = false

        activeThreats = threatsFound

        scanProgress = 1f

        securityScore = when {

            threatsFound == 0 -> 98

            threatsFound <= 3 -> 78

            threatsFound <= 8 -> 52

            else -> 30
        }

        lastScanTime = "Just now"
    }

    fun updateNetworkSpeed(
        upload: Float,
        download: Float
    ) {

        uploadSpeed = upload

        downloadSpeed = download
    }

    fun logout() {

        isUserLoggedIn = false

        currentUsername = ""

        currentUserEmail = ""

        subscriptionActive = false
    }

    fun login(
        username: String,
        email: String
    ) {

        isUserLoggedIn = true

        currentUsername = username

        currentUserEmail = email
    }
}
