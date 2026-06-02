package com.sentrix.ui.common

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

object UIConstants {

    // ----------------------------------------------------------------
    // COLORS
    // ----------------------------------------------------------------

    val PrimaryBlue = Color(0xFF2563EB)
    val SecondaryBlue = Color(0xFF38BDF8)

    val SuccessGreen = Color(0xFF22C55E)
    val WarningYellow = Color(0xFFFACC15)
    val DangerRed = Color(0xFFEF4444)

    val BackgroundDark = Color(0xFF020617)
    val SurfaceDark = Color(0xFF0F172A)
    val CardDark = Color(0xFF111827)
    val BorderDark = Color(0xFF1E293B)

    val TextPrimary = Color(0xFFFFFFFF)
    val TextSecondary = Color(0xFFCBD5E1)
    val TextMuted = Color(0xFF94A3B8)
    val TextDisabled = Color(0xFF64748B)

    // ----------------------------------------------------------------
    // DIMENSIONS
    // ----------------------------------------------------------------

    val ScreenPadding = 16.dp
    val CardPadding = 20.dp
    val ItemPadding = 18.dp

    val CornerRadiusSmall = 12.dp
    val CornerRadiusMedium = 18.dp
    val CornerRadiusLarge = 24.dp
    val CornerRadiusXLarge = 28.dp

    val IconContainerSize = 48.dp
    val IconSize = 24.dp

    val ButtonHeight = 56.dp

    val SectionSpacing = 14.dp
    val ContentSpacing = 10.dp
    val LargeSpacing = 24.dp

    // ----------------------------------------------------------------
    // ANIMATION
    // ----------------------------------------------------------------

    const val AnimationDurationShort = 300
    const val AnimationDurationMedium = 700
    const val AnimationDurationLong = 1500

    // ----------------------------------------------------------------
    // SECURITY STATUS
    // ----------------------------------------------------------------

    const val SECURITY_SECURED = "Secured"
    const val SECURITY_WARNING = "Warning"
    const val SECURITY_CRITICAL = "Critical"

    // ----------------------------------------------------------------
    // GRAPH VALUES
    // ----------------------------------------------------------------

    const val DefaultSecurityScore = 92
    const val MaxGraphPoints = 7

    // ----------------------------------------------------------------
    // SUBSCRIPTION TYPES
    // ----------------------------------------------------------------

    const val PLAN_FREE = "Free"
    const val PLAN_PRO = "Pro"
    const val PLAN_ENTERPRISE = "Enterprise"

    // ----------------------------------------------------------------
    // SETTINGS
    // ----------------------------------------------------------------

    const val THEME_DARK = "Dark"
    const val THEME_LIGHT = "Light"
    const val THEME_SYSTEM = "System"

    // ----------------------------------------------------------------
    // THREAT LEVELS
    // ----------------------------------------------------------------

    const val THREAT_LOW = "Low"
    const val THREAT_MEDIUM = "Medium"
    const val THREAT_HIGH = "High"

    // ----------------------------------------------------------------
    // NETWORK STATUS
    // ----------------------------------------------------------------

    const val NETWORK_SECURE = "Secure"
    const val NETWORK_MONITORING = "Monitoring"
    const val NETWORK_BLOCKED = "Blocked"

    // ----------------------------------------------------------------
    // APP INFO
    // ----------------------------------------------------------------

    const val APP_NAME = "SentriX"
    const val APP_VERSION = "v1.0.0"

    const val COMPANY_NAME = "Kyro-Core"

    // ----------------------------------------------------------------
    // PLACEHOLDER DATA
    // ----------------------------------------------------------------

    val WeeklyThreatData = listOf(
        180f,
        120f,
        150f,
        90f,
        110f,
        70f,
        95f
    )

    val UploadTrafficData = listOf(
        40f,
        65f,
        52f,
        88f,
        60f,
        92f,
        70f
    )

    val DownloadTrafficData = listOf(
        25f,
        48f,
        35f,
        72f,
        50f,
        80f,
        58f
    )
}
