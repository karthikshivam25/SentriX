package com.sentrix.core.constants

object UIConstants {

    /* ============================================================
     * UI ANIMATION DURATIONS
     * ============================================================ */

    const val ANIMATION_FAST = 150L
    const val ANIMATION_NORMAL = 300L
    const val ANIMATION_SLOW = 600L

    const val SPLASH_SCREEN_DELAY = 2500L

    /* ============================================================
     * UI DIMENSIONS
     * ============================================================ */

    const val CORNER_RADIUS_SMALL = 4
    const val CORNER_RADIUS_MEDIUM = 8
    const val CORNER_RADIUS_LARGE = 16
    const val CORNER_RADIUS_EXTRA_LARGE = 24

    const val ELEVATION_LOW = 2
    const val ELEVATION_MEDIUM = 6
    const val ELEVATION_HIGH = 12

    /* ============================================================
     * ALPHA VALUES
     * ============================================================ */

    const val ALPHA_DISABLED = 0.5f
    const val ALPHA_ENABLED = 1.0f
    const val ALPHA_OVERLAY = 0.7f

    /* ============================================================
     * PROGRESS VALUES
     * ============================================================ */

    const val PROGRESS_MIN = 0
    const val PROGRESS_MAX = 100

    /* ============================================================
     * DASHBOARD CARD TYPES
     * ============================================================ */

    const val CARD_SECURITY_SCORE =
        "CARD_SECURITY_SCORE"

    const val CARD_THREAT_MONITOR =
        "CARD_THREAT_MONITOR"

    const val CARD_NETWORK_SECURITY =
        "CARD_NETWORK_SECURITY"

    const val CARD_PERMISSION_ANALYSIS =
        "CARD_PERMISSION_ANALYSIS"

    const val CARD_REALTIME_PROTECTION =
        "CARD_REALTIME_PROTECTION"

    /* ============================================================
     * CHART TYPES
     * ============================================================ */

    const val CHART_LINE = "LINE_CHART"
    const val CHART_BAR = "BAR_CHART"
    const val CHART_PIE = "PIE_CHART"
    const val CHART_RADAR = "RADAR_CHART"

    /* ============================================================
     * UI STATES
     * ============================================================ */

    const val STATE_LOADING = "STATE_LOADING"
    const val STATE_SUCCESS = "STATE_SUCCESS"
    const val STATE_ERROR = "STATE_ERROR"
    const val STATE_EMPTY = "STATE_EMPTY"

    /* ============================================================
     * DIALOG TYPES
     * ============================================================ */

    const val DIALOG_WARNING = "DIALOG_WARNING"
    const val DIALOG_ERROR = "DIALOG_ERROR"
    const val DIALOG_SUCCESS = "DIALOG_SUCCESS"
    const val DIALOG_CONFIRMATION =
        "DIALOG_CONFIRMATION"

    /* ============================================================
     * THEME MODES
     * ============================================================ */

    const val THEME_LIGHT = "LIGHT"
    const val THEME_DARK = "DARK"
    const val THEME_SYSTEM = "SYSTEM"

    /* ============================================================
     * NAVIGATION ROUTES
     * ============================================================ */

    const val ROUTE_SPLASH = "route_splash"
    const val ROUTE_LOGIN = "route_login"
    const val ROUTE_REGISTER = "route_register"
    const val ROUTE_DASHBOARD = "route_dashboard"
    const val ROUTE_SCANNER = "route_scanner"
    const val ROUTE_REPORTS = "route_reports"
    const val ROUTE_SETTINGS = "route_settings"
    const val ROUTE_PROFILE = "route_profile"

    /* ============================================================
     * BOTTOM NAVIGATION ITEMS
     * ============================================================ */

    const val NAV_HOME = "NAV_HOME"
    const val NAV_SCANNER = "NAV_SCANNER"
    const val NAV_ANALYTICS = "NAV_ANALYTICS"
    const val NAV_NOTIFICATIONS =
        "NAV_NOTIFICATIONS"

    const val NAV_SETTINGS = "NAV_SETTINGS"

    /* ============================================================
     * UI PAGINATION
     * ============================================================ */

    const val DEFAULT_PAGE_SIZE = 20
    const val PAGINATION_THRESHOLD = 5

    /* ============================================================
     * TOOLTIP TYPES
     * ============================================================ */

    const val TOOLTIP_INFO = "TOOLTIP_INFO"
    const val TOOLTIP_WARNING = "TOOLTIP_WARNING"
    const val TOOLTIP_SECURITY = "TOOLTIP_SECURITY"

    /* ============================================================
     * SNACKBAR TYPES
     * ============================================================ */

    const val SNACKBAR_SUCCESS =
        "SNACKBAR_SUCCESS"

    const val SNACKBAR_ERROR =
        "SNACKBAR_ERROR"

    const val SNACKBAR_WARNING =
        "SNACKBAR_WARNING"

    const val SNACKBAR_INFO =
        "SNACKBAR_INFO"

    /* ============================================================
     * LIST VIEW TYPES
     * ============================================================ */

    const val VIEW_TYPE_GRID = "GRID"
    const val VIEW_TYPE_LIST = "LIST"

    /* ============================================================
     * SECURITY UI INDICATORS
     * ============================================================ */

    const val INDICATOR_SAFE = "SAFE"
    const val INDICATOR_WARNING = "WARNING"
    const val INDICATOR_DANGER = "DANGER"
    const val INDICATOR_CRITICAL = "CRITICAL"

    /* ============================================================
     * UI LOGGING
     * ============================================================ */

    const val UI_LOG_TAG = "SENTRIX_UI"

}
