package com.sentrix.ui.navigation

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.sentrix.ui.screens.dashboard.DashboardScreen
import com.sentrix.ui.screens.home.HomeScreen
import com.sentrix.ui.screens.login.LoginScreen
import com.sentrix.ui.screens.onboarding.OnboardingScreen
import com.sentrix.ui.screens.scan.ScanScreen
import com.sentrix.ui.screens.settings.SettingsScreen
import com.sentrix.ui.screens.splash.SplashScreen
import com.sentrix.ui.screens.threats.ThreatsScreen
import com.sentrix.ui.screens.vpn.VpnScreen

@Composable
fun SentriXNavGraph(
    modifier: Modifier = Modifier,
    navController: NavHostController = rememberNavController(),
    startDestination: String = NavRoutes.SPLASH
) {

    NavHost(
        navController = navController,
        startDestination = startDestination,
        modifier = modifier
    ) {

        // SPLASH
        composable(NavRoutes.SPLASH) {

            SplashScreen(
                onNavigateToHome = {
                    navController.navigate(NavRoutes.HOME) {
                        popUpTo(NavRoutes.SPLASH) {
                            inclusive = true
                        }
                    }
                }
            )
        }

        // ONBOARDING
        composable(NavRoutes.ONBOARDING) {

            OnboardingScreen(
                onFinish = {
                    navController.navigate(NavRoutes.LOGIN) {
                        popUpTo(NavRoutes.ONBOARDING) {
                            inclusive = true
                        }
                    }
                }
            )
        }

        // LOGIN
        composable(NavRoutes.LOGIN) {

            LoginScreen(
                onLoginSuccess = {
                    navController.navigate(NavRoutes.DASHBOARD) {
                        popUpTo(NavRoutes.LOGIN) {
                            inclusive = true
                        }
                    }
                }
            )
        }

        // HOME
        composable(NavRoutes.HOME) {

            HomeScreen(
                onNavigateToVpn = {
                    navController.navigate(NavRoutes.VPN)
                },
                onNavigateToScan = {
                    navController.navigate(NavRoutes.SCAN)
                },
                onNavigateToThreats = {
                    navController.navigate(NavRoutes.THREATS)
                },
                onNavigateToSettings = {
                    navController.navigate(NavRoutes.SETTINGS)
                }
            )
        }

        // DASHBOARD
        composable(NavRoutes.DASHBOARD) {

            DashboardScreen(
                onOpenVpn = {
                    navController.navigate(NavRoutes.VPN)
                },
                onOpenThreats = {
                    navController.navigate(NavRoutes.THREATS)
                },
                onOpenSettings = {
                    navController.navigate(NavRoutes.SETTINGS)
                }
            )
        }

        // VPN
        composable(NavRoutes.VPN) {

            VpnScreen(
                onBack = {
                    navController.popBackStack()
                }
            )
        }

        // SCAN
        composable(NavRoutes.SCAN) {

            ScanScreen(
                onBack = {
                    navController.popBackStack()
                }
            )
        }

        // THREATS
        composable(NavRoutes.THREATS) {

            ThreatsScreen(
                onBack = {
                    navController.popBackStack()
                }
            )
        }

        // SETTINGS
        composable(NavRoutes.SETTINGS) {

            SettingsScreen(
                onBack = {
                    navController.popBackStack()
                }
            )
        }
    }
}
