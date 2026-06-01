package com.sentrix.ui.navigation

import androidx.navigation.NavDeepLink
import androidx.navigation.navDeepLink

object DeepLinks {

    // --------------------------------------------------
    // APP BASE
    // --------------------------------------------------

    private const val BASE_URI = "https://www.sentrixsecurity.com"

    // --------------------------------------------------
    // AUTH
    // --------------------------------------------------

    val loginDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/login"
        }
    )

    val registerDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/register"
        }
    )

    val forgotPasswordDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/forgot-password"
        }
    )

    // --------------------------------------------------
    // MAIN
    // --------------------------------------------------

    val homeDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/home"
        }
    )

    val dashboardDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/dashboard"
        }
    )

    // --------------------------------------------------
    // SECURITY MODULES
    // --------------------------------------------------

    val vpnDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/vpn"
        }
    )

    val scanDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/scan"
        }
    )

    val threatsDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/threats"
        }
    )

    val firewallDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/firewall"
        }
    )

    // --------------------------------------------------
    // SETTINGS
    // --------------------------------------------------

    val settingsDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/settings"
        }
    )

    val profileDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/profile"
        }
    )

    val privacyDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/privacy"
        }
    )

    // --------------------------------------------------
    // PREMIUM
    // --------------------------------------------------

    val premiumDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/premium"
        }
    )

    val paymentDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/payment"
        }
    )

    // --------------------------------------------------
    // SUPPORT
    // --------------------------------------------------

    val helpDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/help"
        }
    )

    val aboutDeepLinks: List<NavDeepLink> = listOf(
        navDeepLink {
            uriPattern = "$BASE_URI/about"
        }
    )
}
