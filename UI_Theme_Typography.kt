package com.sentrix.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp

/*
|--------------------------------------------------------------------------
| SENTRIX TYPOGRAPHY ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise typography architecture for SentriX.
|
| This file controls:
|
| ✔ Global Typography
| ✔ Responsive Typography
| ✔ Dynamic Font Scaling
| ✔ Accessibility Typography
| ✔ Dashboard Typography
| ✔ Security Typography
| ✔ AI Typography
| ✔ Terminal Typography
| ✔ Cyberpunk Typography
| ✔ Military Typography
| ✔ AMOLED Typography
| ✔ Tablet/Desktop Scaling
| ✔ Multi-language Ready System
|
|--------------------------------------------------------------------------
| IMPORTANT RULES
|--------------------------------------------------------------------------
|
| NEVER hardcode:
|
| - fontSize
| - lineHeight
| - letterSpacing
| - fontWeight
|
| Always use centralized typography presets.
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   FONT FAMILY SYSTEM
   ========================================================= */

object SentriXFonts {

    val Primary = FontFamily.Default

    val Terminal = FontFamily.Monospace

    val Cyberpunk = FontFamily.SansSerif

    val Military = FontFamily.Serif
}



/* =========================================================
   TYPOGRAPHY SCALE ENGINE
   ========================================================= */

object TypographyScale {

    const val Compact = 0.90f

    const val Normal = 1.0f

    const val Tablet = 1.08f

    const val Desktop = 1.16f

    const val Accessibility = 1.30f

    const val UltraAccessibility = 1.50f
}



/* =========================================================
   DEVICE RESPONSIVE ENGINE
   ========================================================= */

@Composable
fun rememberTypographyScale(): Float {

    val configuration = LocalConfiguration.current

    return when {

        configuration.screenWidthDp >= 1400 ->
            TypographyScale.Desktop

        configuration.screenWidthDp >= 900 ->
            TypographyScale.Tablet

        else ->
            TypographyScale.Normal
    }
}



/* =========================================================
   RESPONSIVE FONT GENERATOR
   ========================================================= */

@Composable
fun responsiveSp(base: Int): TextUnit {

    val scale = rememberTypographyScale()

    return (base * scale).sp
}



/* =========================================================
   TYPOGRAPHY MODES
   ========================================================= */

enum class TypographyMode {

    DEFAULT,

    CYBERPUNK,

    MILITARY,

    AMOLED,

    ACCESSIBILITY,

    COMPACT
}



/* =========================================================
   BASE TYPOGRAPHY FACTORY
   ========================================================= */

fun sentrixTextStyle(

    fontFamily: FontFamily = SentriXFonts.Primary,

    fontWeight: FontWeight = FontWeight.Normal,

    fontSize: TextUnit,

    lineHeight: TextUnit = fontSize,

    letterSpacing: TextUnit = 0.sp

): TextStyle {

    return TextStyle(

        fontFamily = fontFamily,

        fontWeight = fontWeight,

        fontSize = fontSize,

        lineHeight = lineHeight,

        letterSpacing = letterSpacing
    )
}



/* =========================================================
   HEADLINE TYPOGRAPHY
   ========================================================= */

object HeadlineTypography {

    val Hero = sentrixTextStyle(

        fontWeight = FontWeight.ExtraBold,

        fontSize = 48.sp,

        lineHeight = 56.sp,

        letterSpacing = (-1).sp
    )

    val Huge = sentrixTextStyle(

        fontWeight = FontWeight.ExtraBold,

        fontSize = 40.sp,

        lineHeight = 48.sp
    )

    val Large = sentrixTextStyle(

        fontWeight = FontWeight.Bold,

        fontSize = 34.sp,

        lineHeight = 40.sp
    )

    val Medium = sentrixTextStyle(

        fontWeight = FontWeight.SemiBold,

        fontSize = 28.sp,

        lineHeight = 34.sp
    )

    val Small = sentrixTextStyle(

        fontWeight = FontWeight.SemiBold,

        fontSize = 22.sp,

        lineHeight = 28.sp
    )
}



/* =========================================================
   BODY TYPOGRAPHY
   ========================================================= */

object BodyTypography {

    val Large = sentrixTextStyle(

        fontSize = 18.sp,

        lineHeight = 30.sp
    )

    val Medium = sentrixTextStyle(

        fontSize = 16.sp,

        lineHeight = 26.sp
    )

    val Small = sentrixTextStyle(

        fontSize = 14.sp,

        lineHeight = 22.sp
    )

    val Tiny = sentrixTextStyle(

        fontSize = 12.sp,

        lineHeight = 18.sp
    )
}



/* =========================================================
   BUTTON TYPOGRAPHY
   ========================================================= */

object ButtonTypography {

    val Large = sentrixTextStyle(

        fontWeight = FontWeight.Bold,

        fontSize = 18.sp,

        lineHeight = 22.sp
    )

    val Medium = sentrixTextStyle(

        fontWeight = FontWeight.SemiBold,

        fontSize = 16.sp,

        lineHeight = 20.sp
    )

    val Small = sentrixTextStyle(

        fontWeight = FontWeight.Medium,

        fontSize = 14.sp,

        lineHeight = 18.sp
    )
}



/* =========================================================
   DASHBOARD TYPOGRAPHY
   ========================================================= */

object DashboardTypography {

    val DashboardTitle = sentrixTextStyle(

        fontWeight = FontWeight.Bold,

        fontSize = 30.sp,

        lineHeight = 36.sp
    )

    val WidgetTitle = sentrixTextStyle(

        fontWeight = FontWeight.SemiBold,

        fontSize = 20.sp,

        lineHeight = 26.sp
    )

    val Metric = sentrixTextStyle(

        fontWeight = FontWeight.ExtraBold,

        fontSize = 36.sp,

        lineHeight = 42.sp
    )

    val Label = sentrixTextStyle(

        fontWeight = FontWeight.Medium,

        fontSize = 14.sp,

        lineHeight = 18.sp
    )
}



/* =========================================================
   SECURITY TYPOGRAPHY
   ========================================================= */

object SecurityTypography {

    val ThreatCritical = sentrixTextStyle(

        fontWeight = FontWeight.ExtraBold,

        fontSize = 22.sp,

        lineHeight = 28.sp
    )

    val ThreatWarning = sentrixTextStyle(

        fontWeight = FontWeight.Bold,

        fontSize = 18.sp,

        lineHeight = 24.sp
    )

    val ThreatNormal = sentrixTextStyle(

        fontWeight = FontWeight.Medium,

        fontSize = 16.sp,

        lineHeight = 22.sp
    )
}



/* =========================================================
   TERMINAL TYPOGRAPHY
   ========================================================= */

object TerminalTypography {

    val Header = sentrixTextStyle(

        fontFamily = SentriXFonts.Terminal,

        fontWeight = FontWeight.Bold,

        fontSize = 16.sp,

        lineHeight = 22.sp
    )

    val Body = sentrixTextStyle(

        fontFamily = SentriXFonts.Terminal,

        fontSize = 14.sp,

        lineHeight = 20.sp
    )

    val Tiny = sentrixTextStyle(

        fontFamily = SentriXFonts.Terminal,

        fontSize = 12.sp,

        lineHeight = 18.sp
    )
}



/* =========================================================
   AI TYPOGRAPHY
   ========================================================= */

object AITypography {

    val Scanner = sentrixTextStyle(

        fontFamily = SentriXFonts.Terminal,

        fontWeight = FontWeight.Medium,

        fontSize = 14.sp,

        lineHeight = 18.sp,

        letterSpacing = 1.sp
    )

    val AIStatus = sentrixTextStyle(

        fontWeight = FontWeight.Bold,

        fontSize = 16.sp,

        lineHeight = 20.sp,

        letterSpacing = 0.5.sp
    )

    val Prediction = sentrixTextStyle(

        fontWeight = FontWeight.SemiBold,

        fontSize = 18.sp,

        lineHeight = 24.sp
    )
}



/* =========================================================
   CYBERPUNK TYPOGRAPHY PACK
   ========================================================= */

object CyberpunkTypography {

    val Hero = sentrixTextStyle(

        fontFamily = SentriXFonts.Cyberpunk,

        fontWeight = FontWeight.ExtraBold,

        fontSize = 42.sp,

        lineHeight = 48.sp,

        letterSpacing = 2.sp
    )

    val Body = sentrixTextStyle(

        fontFamily = SentriXFonts.Cyberpunk,

        fontSize = 16.sp,

        lineHeight = 24.sp,

        letterSpacing = 1.sp
    )
}



/* =========================================================
   MILITARY TYPOGRAPHY PACK
   ========================================================= */

object MilitaryTypography {

    val Header = sentrixTextStyle(

        fontFamily = SentriXFonts.Military,

        fontWeight = FontWeight.Bold,

        fontSize = 32.sp,

        lineHeight = 38.sp
    )

    val Body = sentrixTextStyle(

        fontFamily = SentriXFonts.Military,

        fontSize = 16.sp,

        lineHeight = 24.sp
    )
}



/* =========================================================
   ACCESSIBILITY TYPOGRAPHY
   ========================================================= */

object AccessibilityTypography {

    val LargeHeadline = sentrixTextStyle(

        fontWeight = FontWeight.ExtraBold,

        fontSize = 44.sp,

        lineHeight = 54.sp
    )

    val LargeBody = sentrixTextStyle(

        fontSize = 22.sp,

        lineHeight = 36.sp
    )
}



/* =========================================================
   MULTI LANGUAGE TYPOGRAPHY READY
   ========================================================= */

object LanguageTypography {

    val English = SentriXFonts.Primary

    val Japanese = FontFamily.SansSerif

    val Arabic = FontFamily.Serif

    val Tamil = FontFamily.SansSerif

    val Korean = FontFamily.SansSerif
}



/* =========================================================
   TEXT OVERFLOW SYSTEM
   ========================================================= */

object TextOverflowSystem {

    val Ellipsis = TextOverflow.Ellipsis

    val Clip = TextOverflow.Clip

    val Visible = TextOverflow.Visible
}



/* =========================================================
   TYPOGRAPHY PRESETS
   ========================================================= */

@Immutable
object TypographyPresets {

    val Default = Typography(

        headlineLarge = HeadlineTypography.Large,

        headlineMedium = HeadlineTypography.Medium,

        headlineSmall = HeadlineTypography.Small,

        bodyLarge = BodyTypography.Large,

        bodyMedium = BodyTypography.Medium,

        bodySmall = BodyTypography.Small,

        titleLarge = DashboardTypography.DashboardTitle,

        titleMedium = DashboardTypography.WidgetTitle,

        labelLarge = ButtonTypography.Large,

        labelMedium = ButtonTypography.Medium
    )

    val Cyberpunk = Typography(

        headlineLarge = CyberpunkTypography.Hero,

        bodyLarge = CyberpunkTypography.Body
    )

    val Military = Typography(

        headlineLarge = MilitaryTypography.Header,

        bodyLarge = MilitaryTypography.Body
    )

    val Accessibility = Typography(

        headlineLarge = AccessibilityTypography.LargeHeadline,

        bodyLarge = AccessibilityTypography.LargeBody
    )
}



/* =========================================================
   TYPOGRAPHY MANAGER
   ========================================================= */

object SentriXTypographyManager {

    fun getTypography(

        mode: TypographyMode

    ): Typography {

        return when (mode) {

            TypographyMode.CYBERPUNK ->
                TypographyPresets.Cyberpunk

            TypographyMode.MILITARY ->
                TypographyPresets.Military

            TypographyMode.ACCESSIBILITY ->
                TypographyPresets.Accessibility

            else ->
                TypographyPresets.Default
        }
    }
}



/* =========================================================
   FUTURE TYPOGRAPHY EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive readability
| ✔ Runtime font switching
| ✔ Neural readability optimization
| ✔ Foldable typography engine
| ✔ VR/AR typography rendering
| ✔ Dynamic accessibility engine
| ✔ Live enterprise branding
| ✔ Real-time multilingual rendering
| ✔ Holographic text rendering
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX TYPOGRAPHY ENGINE
|--------------------------------------------------------------------------
*/
