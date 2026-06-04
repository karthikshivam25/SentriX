package com.sentrix.core.extensions

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.OnBackPressedDispatcher
import androidx.navigation.NavController
import androidx.navigation.NavDirections
import androidx.navigation.NavOptions
import androidx.navigation.Navigator
import androidx.navigation.navOptions

/**
 * Navigation Extensions
 * SentriX Core Module
 */

/* -------------------------------------------------------------------------
 * NavController Helpers
 * ------------------------------------------------------------------------- */

fun NavController.navigateSafe(
    route: String
) {
    runCatching {
        navigate(route)
    }
}

fun NavController.navigateSafe(
    route: String,
    builder: NavOptions.Builder.() -> Unit
) {
    runCatching {
        navigate(
            route = route,
            navOptions(builder)
        )
    }
}

fun NavController.navigateSafe(
    directions: NavDirections
) {
    runCatching {
        navigate(directions)
    }
}

fun NavController.navigateSafe(
    resId: Int,
    args: Bundle? = null,
    navOptions: NavOptions? = null,
    navigatorExtras: Navigator.Extras? = null
) {
    runCatching {
        navigate(
            resId,
            args,
            navOptions,
            navigatorExtras
        )
    }
}

/* -------------------------------------------------------------------------
 * Pop Back Stack Helpers
 * ------------------------------------------------------------------------- */

fun NavController.popBackSafe(): Boolean {
    return runCatching {
        popBackStack()
    }.getOrDefault(false)
}

fun NavController.popToDestination(
    destinationId: Int,
    inclusive: Boolean = false
): Boolean {
    return runCatching {
        popBackStack(
            destinationId,
            inclusive
        )
    }.getOrDefault(false)
}

fun NavController.navigateAndClearStack(
    route: String
) {
    navigate(route) {
        popUpTo(graph.startDestinationId) {
            inclusive = true
        }
        launchSingleTop = true
    }
}

/* -------------------------------------------------------------------------
 * Current Destination Helpers
 * ------------------------------------------------------------------------- */

fun NavController.currentRoute(): String? {
    return currentDestination?.route
}

fun NavController.isCurrentRoute(
    route: String
): Boolean {
    return currentDestination?.route == route
}

fun NavController.isCurrentDestination(
    destinationId: Int
): Boolean {
    return currentDestination?.id == destinationId
}

/* -------------------------------------------------------------------------
 * Duplicate Navigation Prevention
 * ------------------------------------------------------------------------- */

fun NavController.navigateIfNotCurrent(
    route: String
) {
    if (currentDestination?.route != route) {
        navigateSafe(route)
    }
}

/* -------------------------------------------------------------------------
 * Activity Navigation
 * ------------------------------------------------------------------------- */

inline fun <reified T : Activity> Context.launchActivity(
    extras: Bundle? = null,
    finishCurrent: Boolean = false
) {
    val intent = Intent(this, T::class.java)

    extras?.let {
        intent.putExtras(it)
    }

    startActivity(intent)

    if (finishCurrent && this is Activity) {
        finish()
    }
}

inline fun <reified T : Activity> Context.launchActivityClearTask(
    extras: Bundle? = null
) {
    val intent = Intent(this, T::class.java).apply {
        flags =
            Intent.FLAG_ACTIVITY_NEW_TASK or
            Intent.FLAG_ACTIVITY_CLEAR_TASK

        extras?.let {
            putExtras(it)
        }
    }

    startActivity(intent)
}

/* -------------------------------------------------------------------------
 * Intent Extras Helpers
 * ------------------------------------------------------------------------- */

fun Intent.putStringExtraSafe(
    key: String,
    value: String?
): Intent {
    putExtra(key, value)
    return this
}

fun Intent.putIntExtraSafe(
    key: String,
    value: Int
): Intent {
    putExtra(key, value)
    return this
}

fun Intent.putBooleanExtraSafe(
    key: String,
    value: Boolean
): Intent {
    putExtra(key, value)
    return this
}

fun Intent.putLongExtraSafe(
    key: String,
    value: Long
): Intent {
    putExtra(key, value)
    return this
}

/* -------------------------------------------------------------------------
 * Back Navigation Helpers
 * ------------------------------------------------------------------------- */

fun Activity.goBack() {
    onBackPressedDispatcher.onBackPressed()
}

fun OnBackPressedDispatcher.handleBack(
    action: () -> Unit
) {
    action()
}

/* -------------------------------------------------------------------------
 * Security Navigation Helpers
 * ------------------------------------------------------------------------- */

fun NavController.navigateToThreatDetails(
    threatId: String
) {
    navigateSafe(
        "threat_details/$threatId"
    )
}

fun NavController.navigateToScanResults(
    scanId: String
) {
    navigateSafe(
        "scan_results/$scanId"
    )
}

fun NavController.navigateToFileAnalysis(
    fileId: String
) {
    navigateSafe(
        "file_analysis/$fileId"
    )
}

fun NavController.navigateToNetworkMonitor() {
    navigateSafe(
        "network_monitor"
    )
}

fun NavController.navigateToVpnDashboard() {
    navigateSafe(
        "vpn_dashboard"
    )
}

fun NavController.navigateToSettings() {
    navigateSafe(
        "settings"
    )
}

/* -------------------------------------------------------------------------
 * Deep Link Helpers
 * ------------------------------------------------------------------------- */

fun NavController.openDeepLink(
    route: String
) {
    navigateSafe(route)
}

/* -------------------------------------------------------------------------
 * Navigation Result Helpers
 * ------------------------------------------------------------------------- */

fun <T> NavController.setResult(
    key: String,
    value: T
) {
    previousBackStackEntry
        ?.savedStateHandle
        ?.set(key, value)
}

fun <T> NavController.getResult(
    key: String
): T? {
    return currentBackStackEntry
        ?.savedStateHandle
        ?.get<T>(key)
}

/* -------------------------------------------------------------------------
 * Single Top Navigation
 * ------------------------------------------------------------------------- */

fun NavController.navigateSingleTop(
    route: String
) {
    navigate(route) {
        launchSingleTop = true
    }
}

/* -------------------------------------------------------------------------
 * Root Navigation
 * ------------------------------------------------------------------------- */

fun NavController.navigateToRoot(
    route: String
) {
    navigate(route) {
        popUpTo(0) {
            inclusive = true
        }
        launchSingleTop = true
    }
}
