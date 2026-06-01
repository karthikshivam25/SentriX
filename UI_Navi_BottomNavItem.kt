package com.sentrix.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.ui.graphics.vector.ImageVector

sealed class BottomNavItem(
    val route: String,
    val title: String,
    val icon: ImageVector
) {

    object Home : BottomNavItem(
        route = NavRoutes.HOME,
        title = "Home",
        icon = Icons.Default.Home
    )

    object Dashboard : BottomNavItem(
        route = NavRoutes.DASHBOARD,
        title = "Dashboard",
        icon = Icons.Default.Dashboard
    )

    object VPN : BottomNavItem(
        route = NavRoutes.VPN,
        title = "VPN",
        icon = Icons.Default.Security
    )

    object Scan : BottomNavItem(
        route = NavRoutes.SCAN,
        title = "Scan",
        icon = Icons.Default.Scanner
    )

    object Threats : BottomNavItem(
        route = NavRoutes.THREATS,
        title = "Threats",
        icon = Icons.Default.Warning
    )

    object Settings : BottomNavItem(
        route = NavRoutes.SETTINGS,
        title = "Settings",
        icon = Icons.Default.Settings
    )

    companion object {

        val bottomNavItems = listOf(
            Home,
            Dashboard,
            VPN,
            Scan,
            Threats,
            Settings
        )
    }
}
