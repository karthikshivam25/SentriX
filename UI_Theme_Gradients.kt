package com.sentrix.ui.theme

import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/*
|--------------------------------------------------------------------------
| SENTRIX GRADIENT ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Centralized gradient rendering system for SentriX.
|
| This file controls:
|
| ✔ Dashboard Gradients
| ✔ Security Threat Gradients
| ✔ AI System Gradients
| ✔ Cyberpunk Neon Gradients
| ✔ Authentication Screen Gradients
| ✔ Glassmorphism Overlays
| ✔ Holographic Layers
| ✔ Analytics Visualizations
| ✔ Animated Gradient Presets
| ✔ Enterprise Branding Gradients
| ✔ AMOLED Optimized Gradients
| ✔ Military Theme Gradients
|
|--------------------------------------------------------------------------
| WHY THIS FILE EXISTS
|--------------------------------------------------------------------------
|
| Enterprise UI systems NEVER hardcode gradients.
|
| BAD:
|
| Brush.linearGradient(...)
|
|--------------------------------------------------------------------------
|
| GOOD:
|
| background(SentriXGradients.Primary)
|
|--------------------------------------------------------------------------
|
| BENEFITS:
|
| ✔ Centralized visual identity
| ✔ Runtime theme switching
| ✔ Brand consistency
| ✔ Easier redesigns
| ✔ GPU optimization
| ✔ Future animation support
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   CORE BRAND GRADIENTS
   ========================================================= */

object BrandGradients {

    val Primary = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF0066FF),

            Color(0xFF00E5FF)
        )
    )

    val Secondary = Brush.linearGradient(

        colors = listOf(

            Color(0xFF0047B3),

            Color(0xFF0066FF),

            Color(0xFF00B0FF)
        )
    )

    val Premium = Brush.linearGradient(

        colors = listOf(

            Color(0xFF00E5FF),

            Color(0xFF0066FF),

            Color(0xFF7B2FFF)
        )
    )
}



/* =========================================================
   BACKGROUND GRADIENTS
   ========================================================= */

object BackgroundGradients {

    val MainBackground = Brush.verticalGradient(

        colors = listOf(

            Color(0xFF070B14),

            Color(0xFF0F172A),

            Color(0xFF111827)
        )
    )

    val DashboardBackground = Brush.linearGradient(

        colors = listOf(

            Color(0xFF081120),

            Color(0xFF111827),

            Color(0xFF1A2338)
        ),

        start = Offset.Zero,

        end = Offset(1200f, 1400f)
    )

    val AMOLEDBackground = Brush.verticalGradient(

        colors = listOf(

            Color(0xFF000000),

            Color(0xFF050505)
        )
    )
}



/* =========================================================
   AUTHENTICATION GRADIENTS
   ========================================================= */

object AuthenticationGradients {

    val LoginBackground = Brush.linearGradient(

        colors = listOf(

            Color(0xFF0A0F1C),

            Color(0xFF13203B),

            Color(0xFF1A2A52)
        )
    )

    val LoginButton = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF0066FF),

            Color(0xFF00E5FF)
        )
    )

    val Verification = Brush.linearGradient(

        colors = listOf(

            Color(0xFF00C853),

            Color(0xFF00E676)
        )
    )
}



/* =========================================================
   SECURITY THREAT GRADIENTS
   ========================================================= */

object ThreatGradients {

    val LowThreat = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF00C853),

            Color(0xFF00E676)
        )
    )

    val MediumThreat = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFFC107),

            Color(0xFFFFD54F)
        )
    )

    val HighThreat = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFF7043),

            Color(0xFFFF9100)
        )
    )

    val CriticalThreat = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFF1744),

            Color(0xFFD50000)
        )
    )

    val SevereThreat = Brush.linearGradient(

        colors = listOf(

            Color(0xFFB00020),

            Color(0xFFFF1744),

            Color(0xFFFF9100)
        )
    )
}



/* =========================================================
   AI SYSTEM GRADIENTS
   ========================================================= */

object AIGradients {

    val Neural = Brush.linearGradient(

        colors = listOf(

            Color(0xFF00E5FF),

            Color(0xFF7C4DFF)
        )
    )

    val Scanner = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF00B0FF),

            Color(0xFF00E5FF),

            Color(0xFF00FFC6)
        )
    )

    val Prediction = Brush.linearGradient(

        colors = listOf(

            Color(0xFF8B5CF6),

            Color(0xFF00E5FF)
        )
    )

    val AIThinking = Brush.sweepGradient(

        colors = listOf(

            Color(0xFF00E5FF),

            Color(0xFF0066FF),

            Color(0xFF7B2FFF),

            Color(0xFF00E5FF)
        )
    )
}



/* =========================================================
   CYBERPUNK MODE GRADIENTS
   ========================================================= */

object CyberpunkGradients {

    val NeonBlue = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF00E5FF),

            Color(0xFF0066FF)
        )
    )

    val NeonPurple = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF8B5CF6),

            Color(0xFFFF00FF)
        )
    )

    val Hologram = Brush.linearGradient(

        colors = listOf(

            Color(0x6600E5FF),

            Color(0x448B5CF6),

            Color(0x220066FF)
        )
    )

    val CyberGrid = Brush.linearGradient(

        colors = listOf(

            Color(0x2200E5FF),

            Color(0x110066FF)
        )
    )
}



/* =========================================================
   GLASSMORPHISM GRADIENTS
   ========================================================= */

object GlassGradients {

    val FrostedGlass = Brush.verticalGradient(

        colors = listOf(

            Color(0x44FFFFFF),

            Color(0x11FFFFFF)
        )
    )

    val PremiumGlass = Brush.linearGradient(

        colors = listOf(

            Color(0x33FFFFFF),

            Color(0x11FFFFFF),

            Color(0x22FFFFFF)
        )
    )

    val BlurOverlay = Brush.verticalGradient(

        colors = listOf(

            Color(0x22000000),

            Color(0x55000000)
        )
    )
}



/* =========================================================
   DASHBOARD CARD GRADIENTS
   ========================================================= */

object DashboardGradients {

    val AnalyticsCard = Brush.linearGradient(

        colors = listOf(

            Color(0xFF102A43),

            Color(0xFF1A3A5C)
        )
    )

    val ThreatCard = Brush.linearGradient(

        colors = listOf(

            Color(0xFF3B1010),

            Color(0xFF5A1717)
        )
    )

    val AIWidget = Brush.linearGradient(

        colors = listOf(

            Color(0xFF1B1B3A),

            Color(0xFF2D1B4E)
        )
    )

    val MonitoringCard = Brush.linearGradient(

        colors = listOf(

            Color(0xFF003F5C),

            Color(0xFF005F73)
        )
    )
}



/* =========================================================
   TERMINAL / CONSOLE GRADIENTS
   ========================================================= */

object TerminalGradients {

    val ConsoleBackground = Brush.verticalGradient(

        colors = listOf(

            Color(0xFF000000),

            Color(0xFF050505)
        )
    )

    val HackerMode = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF00FF66),

            Color(0xFF00C853)
        )
    )

    val WarningConsole = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFF9100),

            Color(0xFFFFC107)
        )
    )
}



/* =========================================================
   MILITARY MODE GRADIENTS
   ========================================================= */

object MilitaryGradients {

    val TacticalGreen = Brush.linearGradient(

        colors = listOf(

            Color(0xFF1B4332),

            Color(0xFF2D6A4F)
        )
    )

    val Radar = Brush.radialGradient(

        colors = listOf(

            Color(0xFF00C853),

            Color(0x1100C853)
        )
    )

    val TacticalPanel = Brush.verticalGradient(

        colors = listOf(

            Color(0xFF0B1D13),

            Color(0xFF132A1D)
        )
    )
}



/* =========================================================
   HOLOGRAPHIC GRADIENTS
   ========================================================= */

object HolographicGradients {

    val HologramBlue = Brush.linearGradient(

        colors = listOf(

            Color(0x5500E5FF),

            Color(0x220066FF),

            Color(0x558B5CF6)
        )
    )

    val HologramPurple = Brush.linearGradient(

        colors = listOf(

            Color(0x558B5CF6),

            Color(0x22FF00FF)
        )
    )
}



/* =========================================================
   ANALYTICS & DATA VISUALIZATION
   ========================================================= */

object AnalyticsGradients {

    val Traffic = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF00E676),

            Color(0xFF00B0FF)
        )
    )

    val CPUUsage = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFFC107),

            Color(0xFFFF9100)
        )
    )

    val MemoryUsage = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFF8B5CF6),

            Color(0xFF00E5FF)
        )
    )

    val CriticalUsage = Brush.horizontalGradient(

        colors = listOf(

            Color(0xFFFF1744),

            Color(0xFFD50000)
        )
    )
}



/* =========================================================
   ENTERPRISE GRADIENT PRESETS
   ========================================================= */

object GradientPresets {

    val Modern = BrandGradients.Primary

    val Premium = BrandGradients.Premium

    val Cyberpunk = CyberpunkGradients.NeonBlue

    val Military = MilitaryGradients.TacticalGreen

    val AMOLED = BackgroundGradients.AMOLEDBackground
}



/* =========================================================
   FUTURE GRADIENT ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Animated live gradients
| ✔ AI adaptive gradients
| ✔ Runtime gradient switching
| ✔ GPU accelerated rendering
| ✔ Dynamic weather gradients
| ✔ Time-based theme gradients
| ✔ VR/AR holographic rendering
| ✔ Neural visualization gradients
| ✔ Dynamic cyber-grid renderer
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX GRADIENT ENGINE
|--------------------------------------------------------------------------
*/
