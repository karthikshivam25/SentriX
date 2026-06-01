package com.sentrix.ui.theme

import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.dp

/*
|--------------------------------------------------------------------------
| SENTRIX SHAPE SYSTEM
|--------------------------------------------------------------------------
|
| PURPOSE:
| Centralized shape architecture for the entire SentriX UI.
|
| This file controls:
|
| ✔ Buttons
| ✔ Cards
| ✔ Dialogs
| ✔ Panels
| ✔ Input Fields
| ✔ Dashboard Widgets
| ✔ Glassmorphism Components
| ✔ Floating Components
| ✔ Security Alert Containers
| ✔ Navigation Drawers
| ✔ AI Monitoring Panels
| ✔ Holographic Containers
| ✔ Compact Enterprise Layouts
|
|--------------------------------------------------------------------------
| WHY THIS FILE IS IMPORTANT
|--------------------------------------------------------------------------
|
| Enterprise applications NEVER hardcode shapes directly.
|
| A centralized shape system allows:
|
| - Consistent UI design
| - Easier future redesigns
| - Dynamic theme switching
| - White-label branding
| - Cyberpunk / Military modes
| - Responsive layouts
| - Animation compatibility
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   BASE CORNER SYSTEM
   ========================================================= */

object SentriXCornerRadius {

    val None = 0.dp

    val ExtraTiny = 2.dp

    val Tiny = 4.dp

    val Small = 8.dp

    val Medium = 12.dp

    val Large = 18.dp

    val ExtraLarge = 24.dp

    val UltraLarge = 32.dp

    val Massive = 42.dp
}



/* =========================================================
   BUTTON SHAPE SYSTEM
   ========================================================= */

object ButtonShapes {

    val Flat = RoundedCornerShape(
        SentriXCornerRadius.None
    )

    val Small = RoundedCornerShape(
        SentriXCornerRadius.Small
    )

    val Medium = RoundedCornerShape(
        SentriXCornerRadius.Medium
    )

    val Large = RoundedCornerShape(
        SentriXCornerRadius.Large
    )

    val Pill = RoundedCornerShape(
        100.dp
    )

    val Circle = CircleShape
}



/* =========================================================
   CARD SHAPE SYSTEM
   ========================================================= */

object CardShapes {

    val Compact = RoundedCornerShape(
        SentriXCornerRadius.Small
    )

    val Standard = RoundedCornerShape(
        SentriXCornerRadius.Medium
    )

    val Premium = RoundedCornerShape(
        SentriXCornerRadius.Large
    )

    val Floating = RoundedCornerShape(
        SentriXCornerRadius.ExtraLarge
    )

    val Dashboard = RoundedCornerShape(
        topStart = 20.dp,
        topEnd = 20.dp,
        bottomStart = 12.dp,
        bottomEnd = 12.dp
    )

    val AIWidget = RoundedCornerShape(
        26.dp
    )

    val SecurityPanel = RoundedCornerShape(
        18.dp
    )
}



/* =========================================================
   INPUT FIELD SHAPES
   ========================================================= */

object InputShapes {

    val Compact = RoundedCornerShape(
        SentriXCornerRadius.Small
    )

    val Standard = RoundedCornerShape(
        SentriXCornerRadius.Medium
    )

    val Rounded = RoundedCornerShape(
        SentriXCornerRadius.ExtraLarge
    )

    val Authentication = RoundedCornerShape(
        16.dp
    )

    val TerminalInput = RoundedCornerShape(
        4.dp
    )
}



/* =========================================================
   DIALOG / POPUP SHAPES
   ========================================================= */

object DialogShapes {

    val Small = RoundedCornerShape(
        16.dp
    )

    val Standard = RoundedCornerShape(
        24.dp
    )

    val Premium = RoundedCornerShape(
        32.dp
    )

    val Glass = RoundedCornerShape(
        28.dp
    )

    val AIAnalysis = RoundedCornerShape(
        topStart = 32.dp,
        topEnd = 32.dp,
        bottomStart = 12.dp,
        bottomEnd = 12.dp
    )
}



/* =========================================================
   NAVIGATION SHAPES
   ========================================================= */

object NavigationShapes {

    val Drawer = RoundedCornerShape(
        topEnd = 28.dp,
        bottomEnd = 28.dp
    )

    val Sidebar = RoundedCornerShape(
        0.dp
    )

    val BottomBar = RoundedCornerShape(
        topStart = 24.dp,
        topEnd = 24.dp
    )

    val NavigationItem = RoundedCornerShape(
        14.dp
    )
}



/* =========================================================
   SECURITY ALERT SHAPES
   ========================================================= */

object AlertShapes {

    val Warning = RoundedCornerShape(
        14.dp
    )

    val Critical = RoundedCornerShape(
        10.dp
    )

    val ThreatPanel = RoundedCornerShape(
        18.dp
    )

    val Emergency = RoundedCornerShape(
        6.dp
    )
}



/* =========================================================
   TERMINAL / CONSOLE SHAPES
   ========================================================= */

object TerminalShapes {

    val Console = RoundedCornerShape(
        8.dp
    )

    val Window = RoundedCornerShape(
        12.dp
    )

    val FloatingConsole = RoundedCornerShape(
        20.dp
    )
}



/* =========================================================
   CYBERPUNK MODE SHAPES
   ========================================================= */

object CyberpunkShapes {

    /*
    |--------------------------------------------------------------------------
    | Sharp futuristic edges
    |--------------------------------------------------------------------------
    */

    val Panel = RoundedCornerShape(
        topStart = 0.dp,
        topEnd = 18.dp,
        bottomStart = 18.dp,
        bottomEnd = 0.dp
    )

    val Button = RoundedCornerShape(
        2.dp
    )

    val Card = RoundedCornerShape(
        10.dp
    )
}



/* =========================================================
   MILITARY MODE SHAPES
   ========================================================= */

object MilitaryShapes {

    /*
    |--------------------------------------------------------------------------
    | More rigid tactical UI
    |--------------------------------------------------------------------------
    */

    val Panel = RoundedCornerShape(
        4.dp
    )

    val Button = RoundedCornerShape(
        2.dp
    )

    val Card = RoundedCornerShape(
        6.dp
    )
}



/* =========================================================
   GLASSMORPHISM SHAPES
   ========================================================= */

object GlassShapes {

    val FrostedCard = RoundedCornerShape(
        28.dp
    )

    val BlurPanel = RoundedCornerShape(
        32.dp
    )

    val FloatingGlass = RoundedCornerShape(
        40.dp
    )
}



/* =========================================================
   AI MODULE SHAPES
   ========================================================= */

object AIShapes {

    val ScannerPanel = RoundedCornerShape(
        24.dp
    )

    val NeuralCard = RoundedCornerShape(
        30.dp
    )

    val PredictionWidget = RoundedCornerShape(
        20.dp
    )

    val AIOrb = CircleShape
}



/* =========================================================
   RESPONSIVE SHAPE SYSTEM
   ========================================================= */

object ResponsiveShapes {

    fun card(isTablet: Boolean): Shape {

        return if (isTablet) {

            RoundedCornerShape(28.dp)

        } else {

            RoundedCornerShape(18.dp)
        }
    }

    fun button(isTablet: Boolean): Shape {

        return if (isTablet) {

            RoundedCornerShape(18.dp)

        } else {

            RoundedCornerShape(12.dp)
        }
    }
}



/* =========================================================
   ACCESSIBILITY SHAPES
   ========================================================= */

object AccessibilityShapes {

    /*
    |--------------------------------------------------------------------------
    | Larger touch-friendly corners
    |--------------------------------------------------------------------------
    */

    val LargeTouchButton = RoundedCornerShape(
        24.dp
    )

    val LargeTouchCard = RoundedCornerShape(
        28.dp
    )
}



/* =========================================================
   ENTERPRISE SHAPE PRESETS
   ========================================================= */

object ShapePresets {

    val Modern = Shapes(

        small = RoundedCornerShape(8.dp),

        medium = RoundedCornerShape(16.dp),

        large = RoundedCornerShape(24.dp)
    )

    val Cyberpunk = Shapes(

        small = CyberpunkShapes.Button,

        medium = CyberpunkShapes.Card,

        large = CyberpunkShapes.Panel
    )

    val Military = Shapes(

        small = MilitaryShapes.Button,

        medium = MilitaryShapes.Card,

        large = MilitaryShapes.Panel
    )

    val Glass = Shapes(

        small = GlassShapes.FrostedCard,

        medium = GlassShapes.BlurPanel,

        large = GlassShapes.FloatingGlass
    )
}



/*
|--------------------------------------------------------------------------
| FUTURE EXPANSION IDEAS
|--------------------------------------------------------------------------
|
| ✔ Animated shape morphing
| ✔ Runtime shape switching
| ✔ AI adaptive component shapes
| ✔ Foldable device shape system
| ✔ VR/AR UI geometry
| ✔ Dynamic holographic panels
| ✔ Gesture optimized shape engine
| ✔ Gaming mode shape pack
|
|--------------------------------------------------------------------------
|
| END OF SENTRIX SHAPE SYSTEM
|
|--------------------------------------------------------------------------
*/
