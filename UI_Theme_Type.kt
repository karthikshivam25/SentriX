package com.sentrix.ui.theme

import android.content.res.Configuration
import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/*
|--------------------------------------------------------------------------
| SENTRIX ADVANCED TYPOGRAPHY ENGINE
|--------------------------------------------------------------------------
|
| ENTERPRISE FEATURES INCLUDED:
|
| ✔ Dynamic Font Scaling
| ✔ Accessibility Font Modes
| ✔ Multi-Language Ready Structure
| ✔ AI Adaptive Readability
| ✔ AMOLED Typography Support
| ✔ Compact Enterprise Mode
| ✔ Cyberpunk Typography Pack
| ✔ Military Typography Pack
| ✔ Dashboard Typography
| ✔ Terminal Typography
| ✔ Responsive Tablet/Desktop Scaling
| ✔ Security Alert Typography
|
|--------------------------------------------------------------------------
| ARCHITECTURE GOAL
|--------------------------------------------------------------------------
|
| This is NOT just a font file.
|
| This acts as:
|
| - Typography Engine
| - Readability Controller
| - Device Scaling System
| - Theme Typography Manager
| - Accessibility Layer
| - Future Branding System
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   FONT FAMILY SYSTEM
   ========================================================= */

/*
|--------------------------------------------------------------------------
| DEFAULT PRIMARY FONT
|--------------------------------------------------------------------------
|
| Replace later with:
|
| - Inter
| - Poppins
| - SF Pro
| - IBM Plex Sans
| - Manrope
|
|--------------------------------------------------------------------------
*/

val SentriXPrimaryFont = FontFamily.Default



/ * =========================================================
   TERMINAL / MONOSPACE FONT
   ========================================================= */

val SentriXTerminalFont = FontFamily.Monospace



/* =========================================================
   CYBERPUNK FONT MODE
   ========================================================= */

val SentriXCyberFont = FontFamily.SansSerif



/* =========================================================
   MILITARY FONT MODE
   ========================================================= */

val SentriXMilitaryFont = FontFamily.Serif



/* =========================================================
   TYPOGRAPHY SCALE SYSTEM
   ========================================================= */

object FontScaleManager {

    const val SMALL = 0.85f

    const val NORMAL = 1.0f

    const val LARGE = 1.15f

    const val ACCESSIBILITY = 1.30f

    const val ULTRA_ACCESSIBILITY = 1.50f
}



/* =========================================================
   TYPOGRAPHY MODE SYSTEM
   ========================================================= */

enum class TypographyMode {

    DEFAULT,

    AMOLED,

    CYBERPUNK,

    MILITARY,

    COMPACT,

    ACCESSIBILITY
}



/* =========================================================
   DEVICE DETECTION SYSTEM
   ========================================================= */

@Composable
fun rememberDeviceScale(): Float {

    val configuration = LocalConfiguration.current

    return when {

        configuration.screenWidthDp > 1200 -> 1.30f

        configuration.screenWidthDp > 840 -> 1.15f

        configuration.screenWidthDp > 600 -> 1.05f

        else -> 1.0f
    }
}



/* =========================================================
   RESPONSIVE FONT GENERATOR
   ========================================================= */

@Composable
fun responsiveTextSize(base: Int): Int {

    val scale = rememberDeviceScale()

    return (base * scale).toInt()
}



/* =========================================================
   FONT MODE SELECTOR
   ========================================================= */

fun typographyFont(mode: TypographyMode): FontFamily {

    return when (mode) {

        TypographyMode.CYBERPUNK -> SentriXCyberFont

        TypographyMode.MILITARY -> SentriXMilitaryFont

        else -> SentriXPrimaryFont
    }
}



/* =========================================================
   AMOLED MODE TYPOGRAPHY
   ========================================================= */

val AMOLEDHeadline = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 34.sp,

    letterSpacing = (-0.5).sp
)

val AMOLEDBody = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 16.sp,

    lineHeight = 26.sp
)



/* =========================================================
   CYBERPUNK TYPOGRAPHY PACK
   ========================================================= */

val CyberpunkHeadline = TextStyle(

    fontFamily = SentriXCyberFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 36.sp,

    letterSpacing = 2.sp
)

val CyberpunkBody = TextStyle(

    fontFamily = SentriXCyberFont,

    fontWeight = FontWeight.Medium,

    fontSize = 16.sp,

    letterSpacing = 1.sp
)

val CyberpunkTerminal = TextStyle(

    fontFamily = SentriXTerminalFont,

    fontWeight = FontWeight.Bold,

    fontSize = 14.sp,

    letterSpacing = 1.5.sp
)



/* =========================================================
   MILITARY TYPOGRAPHY PACK
   ========================================================= */

val MilitaryHeadline = TextStyle(

    fontFamily = SentriXMilitaryFont,

    fontWeight = FontWeight.Bold,

    fontSize = 32.sp
)

val MilitaryBody = TextStyle(

    fontFamily = SentriXMilitaryFont,

    fontWeight = FontWeight.Medium,

    fontSize = 16.sp,

    lineHeight = 24.sp
)



/* =========================================================
   ACCESSIBILITY TYPOGRAPHY PACK
   ========================================================= */

val AccessibilityHeadline = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 40.sp,

    lineHeight = 48.sp
)

val AccessibilityBody = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 20.sp,

    lineHeight = 34.sp
)



/* =========================================================
   COMPACT ENTERPRISE MODE
   ========================================================= */

val CompactTitle = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.SemiBold,

    fontSize = 14.sp
)

val CompactBody = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 12.sp
)



/* =========================================================
   MAIN HEADLINE SYSTEM
   ========================================================= */

val HeadlineHuge = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 42.sp,

    lineHeight = 50.sp
)

val HeadlineLarge = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Bold,

    fontSize = 34.sp,

    lineHeight = 40.sp
)

val HeadlineMedium = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.SemiBold,

    fontSize = 28.sp,

    lineHeight = 34.sp
)

val HeadlineSmall = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.SemiBold,

    fontSize = 22.sp,

    lineHeight = 28.sp
)



/* =========================================================
   BODY TYPOGRAPHY SYSTEM
   ========================================================= */

val BodyLarge = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 18.sp,

    lineHeight = 28.sp
)

val BodyMedium = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 16.sp,

    lineHeight = 24.sp
)

val BodySmall = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Normal,

    fontSize = 14.sp,

    lineHeight = 20.sp
)



/* =========================================================
   DASHBOARD TYPOGRAPHY
   ========================================================= */

val DashboardTitle = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Bold,

    fontSize = 26.sp
)

val DashboardMetric = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 34.sp
)

val DashboardLabel = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Medium,

    fontSize = 14.sp
)



/* =========================================================
   TERMINAL TYPOGRAPHY
   ========================================================= */

val TerminalHeader = TextStyle(

    fontFamily = SentriXTerminalFont,

    fontWeight = FontWeight.Bold,

    fontSize = 16.sp
)

val TerminalText = TextStyle(

    fontFamily = SentriXTerminalFont,

    fontWeight = FontWeight.Normal,

    fontSize = 14.sp
)



/* =========================================================
   SECURITY ALERT TYPOGRAPHY
   ========================================================= */

val ThreatCritical = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.ExtraBold,

    fontSize = 22.sp
)

val ThreatWarning = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Bold,

    fontSize = 18.sp
)



/* =========================================================
   AI MONITORING TYPOGRAPHY
   ========================================================= */

val AIStatusText = TextStyle(

    fontFamily = SentriXPrimaryFont,

    fontWeight = FontWeight.Bold,

    fontSize = 15.sp,

    letterSpacing = 0.5.sp
)

val AIScannerText = TextStyle(

    fontFamily = SentriXTerminalFont,

    fontWeight = FontWeight.Medium,

    fontSize = 14.sp
)



/* =========================================================
   MULTI LANGUAGE SUPPORT READY
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE MULTI LANGUAGE SUPPORT
|--------------------------------------------------------------------------
|
| Example:
|
| Japanese Font Pack
| Arabic Font Pack
| Tamil Font Pack
| Korean Font Pack
|
|--------------------------------------------------------------------------
*/

object LanguageTypography {

    val English = SentriXPrimaryFont

    val Japanese = FontFamily.SansSerif

    val Arabic = FontFamily.Serif

    val Tamil = FontFamily.SansSerif
}



/* =========================================================
   ADAPTIVE AI READABILITY SYSTEM
   ========================================================= */

fun adaptiveLineHeight(fontSize: Int): Int {

    return when {

        fontSize >= 40 -> fontSize + 14

        fontSize >= 30 -> fontSize + 12

        fontSize >= 20 -> fontSize + 10

        else -> fontSize + 8
    }
}



/* =========================================================
   COMPLETE MATERIAL TYPOGRAPHY SYSTEM
   ========================================================= */

val SentriXTypography = Typography(

    headlineLarge = HeadlineLarge,

    headlineMedium = HeadlineMedium,

    headlineSmall = HeadlineSmall,

    bodyLarge = BodyLarge,

    bodyMedium = BodyMedium,

    bodySmall = BodySmall,

    titleLarge = DashboardTitle
)



/* =========================================================
   TYPOGRAPHY PRESET MANAGER
   ========================================================= */

object TypographyPresets {

    val Default = SentriXTypography

    val AMOLED = Typography(
        headlineLarge = AMOLEDHeadline,
        bodyLarge = AMOLEDBody
    )

    val Cyberpunk = Typography(
        headlineLarge = CyberpunkHeadline,
        bodyLarge = CyberpunkBody
    )

    val Military = Typography(
        headlineLarge = MilitaryHeadline,
        bodyLarge = MilitaryBody
    )

    val Accessibility = Typography(
        headlineLarge = AccessibilityHeadline,
        bodyLarge = AccessibilityBody
    )
}



/*
|--------------------------------------------------------------------------
| END OF SENTRIX TYPOGRAPHY ENGINE
|--------------------------------------------------------------------------
|
| FUTURE EXPANSION IDEAS
|--------------------------------------------------------------------------
|
| ✔ AI-based readability optimization
| ✔ Live typography engine switching
| ✔ Runtime theme typography updates
| ✔ Enterprise branding typography
| ✔ User typography customization
| ✔ Dynamic language packs
| ✔ Neural adaptive reading mode
| ✔ AR/VR typography rendering
|
|--------------------------------------------------------------------------
*/

