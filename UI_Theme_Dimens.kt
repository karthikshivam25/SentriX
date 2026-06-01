package com.sentrix.ui.theme

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/*
|--------------------------------------------------------------------------
| SENTRIX DIMENSION SYSTEM
|--------------------------------------------------------------------------
|
| PURPOSE:
| Centralized spacing and sizing engine for SentriX.
|
| This file controls:
|
| ✔ Padding
| ✔ Margin
| ✔ Component Sizing
| ✔ Responsive Scaling
| ✔ Dashboard Layout Spacing
| ✔ Card Sizes
| ✔ Button Heights
| ✔ Icon Sizes
| ✔ Grid Systems
| ✔ Navigation Dimensions
| ✔ Touch Targets
| ✔ Tablet/Desktop Scaling
| ✔ Accessibility Layout Scaling
|
|--------------------------------------------------------------------------
| WHY THIS FILE EXISTS
|--------------------------------------------------------------------------
|
| Enterprise applications NEVER hardcode:
|
| - padding values
| - margin values
| - icon sizes
| - spacing
| - layout gaps
| - component heights
|
| Everything should come from a centralized design system.
|
|--------------------------------------------------------------------------
|
| BAD EXAMPLE:
|
| Modifier.padding(13.dp)
|
|--------------------------------------------------------------------------
|
| GOOD EXAMPLE:
|
| Modifier.padding(SentriXSpacing.Medium)
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   BASE SPACING SYSTEM
   ========================================================= */

object SentriXSpacing {

    val None = 0.dp

    val Tiny = 2.dp

    val ExtraSmall = 4.dp

    val Small = 8.dp

    val Medium = 12.dp

    val Large = 16.dp

    val ExtraLarge = 24.dp

    val Huge = 32.dp

    val Massive = 48.dp

    val UltraMassive = 64.dp
}



/* =========================================================
   COMPONENT HEIGHT SYSTEM
   ========================================================= */

object SentriXHeights {

    val Tiny = 24.dp

    val Small = 36.dp

    val Medium = 48.dp

    val Large = 56.dp

    val ExtraLarge = 64.dp

    val Huge = 72.dp

    val Massive = 96.dp
}



/* =========================================================
   BUTTON DIMENSIONS
   ========================================================= */

object ButtonDimensions {

    val SmallHeight = 36.dp

    val MediumHeight = 48.dp

    val LargeHeight = 56.dp

    val ExtraLargeHeight = 64.dp

    val PillHeight = 52.dp

    val CompactWidth = 100.dp

    val MediumWidth = 160.dp

    val LargeWidth = 220.dp

    val MassiveWidth = 320.dp
}



/* =========================================================
   CARD DIMENSIONS
   ========================================================= */

object CardDimensions {

    val CompactWidth = 160.dp

    val CompactHeight = 120.dp

    val StandardWidth = 260.dp

    val StandardHeight = 180.dp

    val DashboardHeight = 220.dp

    val DashboardWidth = 320.dp

    val AnalyticsHeight = 340.dp

    val SecurityPanelHeight = 420.dp

    val FloatingCardHeight = 280.dp
}



/* =========================================================
   ICON SIZE SYSTEM
   ========================================================= */

object IconDimensions {

    val Tiny = 12.dp

    val Small = 16.dp

    val Medium = 24.dp

    val Large = 32.dp

    val ExtraLarge = 48.dp

    val Huge = 64.dp

    val Massive = 96.dp
}



/* =========================================================
   IMAGE DIMENSIONS
   ========================================================= */

object ImageDimensions {

    val AvatarTiny = 24.dp

    val AvatarSmall = 40.dp

    val AvatarMedium = 64.dp

    val AvatarLarge = 96.dp

    val AvatarHuge = 140.dp

    val BannerHeight = 220.dp

    val DashboardGraphic = 300.dp
}



/* =========================================================
   NAVIGATION DIMENSIONS
   ========================================================= */

object NavigationDimensions {

    val BottomBarHeight = 72.dp

    val DrawerWidth = 320.dp

    val SidebarWidth = 90.dp

    val ExpandedSidebarWidth = 280.dp

    val NavigationRailWidth = 88.dp

    val TopBarHeight = 64.dp
}



/* =========================================================
   INPUT FIELD DIMENSIONS
   ========================================================= */

object InputDimensions {

    val SmallHeight = 42.dp

    val MediumHeight = 52.dp

    val LargeHeight = 60.dp

    val SearchBarHeight = 58.dp

    val OTPFieldSize = 64.dp
}



/* =========================================================
   DIALOG DIMENSIONS
   ========================================================= */

object DialogDimensions {

    val CompactWidth = 280.dp

    val StandardWidth = 360.dp

    val LargeWidth = 480.dp

    val PremiumWidth = 640.dp

    val FullscreenPadding = 24.dp
}



/* =========================================================
   GRID & DASHBOARD SYSTEM
   ========================================================= */

object GridDimensions {

    val GridSpacing = 16.dp

    val DashboardGap = 20.dp

    val AnalyticsGap = 24.dp

    val SecurityGap = 18.dp

    val WidgetGap = 14.dp
}



/* =========================================================
   TERMINAL / CONSOLE DIMENSIONS
   ========================================================= */

object TerminalDimensions {

    val ConsoleHeight = 340.dp

    val CommandBarHeight = 52.dp

    val TerminalPadding = 18.dp

    val LogSpacing = 10.dp
}



/* =========================================================
   ACCESSIBILITY DIMENSIONS
   ========================================================= */

object AccessibilityDimensions {

    /*
    |--------------------------------------------------------------------------
    | Larger touch targets
    |--------------------------------------------------------------------------
    */

    val TouchTargetMinimum = 48.dp

    val LargeTouchTarget = 64.dp

    val AccessibilityPadding = 24.dp
}



/* =========================================================
   TABLET / DESKTOP RESPONSIVE SYSTEM
   ========================================================= */

object ResponsiveDimensions {

    fun contentPadding(isTablet: Boolean): Dp {

        return if (isTablet) {

            32.dp

        } else {

            16.dp
        }
    }

    fun dashboardCardWidth(isTablet: Boolean): Dp {

        return if (isTablet) {

            420.dp

        } else {

            320.dp
        }
    }

    fun sidebarWidth(isDesktop: Boolean): Dp {

        return if (isDesktop) {

            320.dp

        } else {

            90.dp
        }
    }
}



/* =========================================================
   DEVICE SIZE DETECTION
   ========================================================= */

@Composable
fun isTabletDevice(): Boolean {

    val configuration = LocalConfiguration.current

    return configuration.screenWidthDp >= 600
}



@Composable
fun isDesktopDevice(): Boolean {

    val configuration = LocalConfiguration.current

    return configuration.screenWidthDp >= 1000
}



/* =========================================================
   CYBERPUNK DIMENSIONS
   ========================================================= */

object CyberpunkDimensions {

    val NeonBorder = 2.dp

    val GridLine = 1.dp

    val HologramPadding = 28.dp

    val CyberPanelHeight = 260.dp
}



/* =========================================================
   MILITARY MODE DIMENSIONS
   ========================================================= */

object MilitaryDimensions {

    val TacticalPadding = 10.dp

    val CompactPanelHeight = 180.dp

    val RadarWidgetSize = 220.dp
}



/* =========================================================
   AI MODULE DIMENSIONS
   ========================================================= */

object AIDimensions {

    val ScannerHeight = 320.dp

    val NeuralWidgetHeight = 240.dp

    val PredictionPanelHeight = 280.dp

    val AIOrbSize = 120.dp
}



/* =========================================================
   ANIMATION DIMENSIONS
   ========================================================= */

object AnimationDimensions {

    val SmallTranslation = 4.dp

    val MediumTranslation = 8.dp

    val LargeTranslation = 16.dp

    val FloatingOffset = 12.dp
}



/* =========================================================
   ENTERPRISE LAYOUT PRESETS
   ========================================================= */

object LayoutPresets {

    val CompactPadding = 8.dp

    val StandardPadding = 16.dp

    val ComfortablePadding = 24.dp

    val PremiumPadding = 32.dp

    val UltraPremiumPadding = 48.dp
}



/* =========================================================
   FUTURE EXPANSION IDEAS
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Foldable device dimensions
| ✔ Dynamic runtime scaling
| ✔ AI adaptive spacing engine
| ✔ VR/AR layout scaling
| ✔ Ultra-wide monitor support
| ✔ Multi-window layout system
| ✔ Gesture optimized layouts
| ✔ Smart dashboard scaling
| ✔ Dynamic widget density
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX DIMENSION SYSTEM
|--------------------------------------------------------------------------
*/
