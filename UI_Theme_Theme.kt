package com.sentrix.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.*
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/*
|--------------------------------------------------------------------------
| SENTRIX MAIN THEME ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| This is the master theme controller of SentriX.
|
| This file connects:
|
| ✔ Colors
| ✔ Typography
| ✔ Shapes
| ✔ Effects
| ✔ Gradients
| ✔ Dimensions
|
|--------------------------------------------------------------------------
| FEATURES INCLUDED
|--------------------------------------------------------------------------
|
| ✔ Dynamic Theme Switching
| ✔ Dark Mode
| ✔ AMOLED Mode
| ✔ Cyberpunk Mode
| ✔ Military Mode
| ✔ Accessibility Mode
| ✔ Enterprise Branding Ready
| ✔ Runtime Theme Updates
| ✔ System Bar Styling
| ✔ Future White Label Support
|
|--------------------------------------------------------------------------
| ARCHITECTURE PURPOSE
|--------------------------------------------------------------------------
|
| This acts as:
|
| - Theme Controller
| - Theme State Engine
| - UI Identity Manager
| - Runtime Theme Manager
| - Enterprise Branding Layer
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   THEME MODES
   ========================================================= */

enum class SentriXThemeMode {

    DARK,

    LIGHT,

    AMOLED,

    CYBERPUNK,

    MILITARY,

    ACCESSIBILITY
}



/* =========================================================
   SENTRIX THEME STATE
   ========================================================= */

object SentriXThemeState {

    var currentTheme by mutableStateOf(
        SentriXThemeMode.DARK
    )

    fun updateTheme(
        mode: SentriXThemeMode
    ) {

        currentTheme = mode
    }
}



/* =========================================================
   DARK COLOR SCHEME
   ========================================================= */

private val SentriXDarkColors = darkColorScheme(

    primary = Color(0xFF0066FF),

    secondary = Color(0xFF00E5FF),

    tertiary = Color(0xFF8B5CF6),

    background = Color(0xFF070B14),

    surface = Color(0xFF111827),

    surfaceVariant = Color(0xFF1A2338),

    onPrimary = Color.White,

    onSecondary = Color.White,

    onBackground = Color.White,

    onSurface = Color.White
)



/* =========================================================
   LIGHT COLOR SCHEME
   ========================================================= */

private val SentriXLightColors = lightColorScheme(

    primary = Color(0xFF0066FF),

    secondary = Color(0xFF00B0FF),

    tertiary = Color(0xFF7B2FFF),

    background = Color(0xFFF5F7FA),

    surface = Color.White,

    surfaceVariant = Color(0xFFE5EAF2),

    onPrimary = Color.White,

    onSecondary = Color.White,

    onBackground = Color.Black,

    onSurface = Color.Black
)



/* =========================================================
   AMOLED COLOR SCHEME
   ========================================================= */

private val SentriXAMOLEDColors = darkColorScheme(

    primary = Color(0xFF00E5FF),

    secondary = Color(0xFF0066FF),

    tertiary = Color(0xFF8B5CF6),

    background = Color.Black,

    surface = Color(0xFF050505),

    surfaceVariant = Color(0xFF101010),

    onPrimary = Color.White,

    onBackground = Color.White,

    onSurface = Color.White
)



/* =========================================================
   CYBERPUNK COLOR SCHEME
   ========================================================= */

private val SentriXCyberpunkColors = darkColorScheme(

    primary = Color(0xFF00E5FF),

    secondary = Color(0xFFFF00FF),

    tertiary = Color(0xFF7B2FFF),

    background = Color(0xFF080312),

    surface = Color(0xFF140A22),

    surfaceVariant = Color(0xFF221133),

    onPrimary = Color.White,

    onBackground = Color.White,

    onSurface = Color.White
)



/* =========================================================
   MILITARY COLOR SCHEME
   ========================================================= */

private val SentriXMilitaryColors = darkColorScheme(

    primary = Color(0xFF2D6A4F),

    secondary = Color(0xFF40916C),

    tertiary = Color(0xFF95D5B2),

    background = Color(0xFF081C15),

    surface = Color(0xFF1B4332),

    surfaceVariant = Color(0xFF2D6A4F),

    onPrimary = Color.White,

    onBackground = Color.White,

    onSurface = Color.White
)



/* =========================================================
   ACCESSIBILITY COLOR SCHEME
   ========================================================= */

private val SentriXAccessibilityColors = darkColorScheme(

    primary = Color(0xFFFFFF00),

    secondary = Color(0xFF00FFFF),

    tertiary = Color(0xFFFF00FF),

    background = Color.Black,

    surface = Color(0xFF101010),

    onPrimary = Color.Black,

    onBackground = Color.White,

    onSurface = Color.White
)



/* =========================================================
   COLOR SCHEME SELECTOR
   ========================================================= */

@Composable
fun sentriXColorScheme(): androidx.compose.material3.ColorScheme {

    return when (
        SentriXThemeState.currentTheme
    ) {

        SentriXThemeMode.LIGHT ->
            SentriXLightColors

        SentriXThemeMode.AMOLED ->
            SentriXAMOLEDColors

        SentriXThemeMode.CYBERPUNK ->
            SentriXCyberpunkColors

        SentriXThemeMode.MILITARY ->
            SentriXMilitaryColors

        SentriXThemeMode.ACCESSIBILITY ->
            SentriXAccessibilityColors

        else ->
            SentriXDarkColors
    }
}



/* =========================================================
   TYPOGRAPHY SELECTOR
   ========================================================= */

@Composable
fun sentriXTypography() = when (

    SentriXThemeState.currentTheme

) {

    SentriXThemeMode.CYBERPUNK ->
        TypographyPresets.Cyberpunk

    SentriXThemeMode.MILITARY ->
        TypographyPresets.Military

    SentriXThemeMode.ACCESSIBILITY ->
        TypographyPresets.Accessibility

    else ->
        TypographyPresets.Default
}



/* =========================================================
   SHAPE SELECTOR
   ========================================================= */

@Composable
fun sentriXShapes() = when (

    SentriXThemeState.currentTheme

) {

    SentriXThemeMode.CYBERPUNK ->
        ShapePresets.Cyberpunk

    SentriXThemeMode.MILITARY ->
        ShapePresets.Military

    else ->
        ShapePresets.Modern
}



/* =========================================================
   SYSTEM BAR ENGINE
   ========================================================= */

@Composable
fun ConfigureSystemBars(

    darkIcons: Boolean

) {

    val view = LocalView.current

    val context = LocalContext.current

    if (!view.isInEditMode) {

        SideEffect {

            val window = (context as Activity).window

            window.statusBarColor =
                Color.Transparent.toArgb()

            window.navigationBarColor =
                Color.Black.toArgb()

            WindowCompat
                .getInsetsController(
                    window,
                    view
                )
                .isAppearanceLightStatusBars =
                darkIcons
        }
    }
}



/* =========================================================
   MAIN THEME WRAPPER
   ========================================================= */

@Composable
fun SentriXTheme(

    useDarkTheme: Boolean = isSystemInDarkTheme(),

    dynamicTheme: Boolean = true,

    content: @Composable () -> Unit

) {

    val colors = sentriXColorScheme()

    val typography = sentriXTypography()

    val shapes = sentriXShapes()



    /*
    |--------------------------------------------------------------------------
    | SYSTEM UI
    |--------------------------------------------------------------------------
    */

    ConfigureSystemBars(

        darkIcons = false
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN MATERIAL THEME
    |--------------------------------------------------------------------------
    */

    MaterialTheme(

        colorScheme = colors,

        typography = typography,

        shapes = shapes,

        content = content
    )
}



/* =========================================================
   ENTERPRISE THEME MANAGER
   ========================================================= */

object EnterpriseThemeManager {

    fun activateDarkMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.DARK
        )
    }

    fun activateAMOLEDMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.AMOLED
        )
    }

    fun activateCyberpunkMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.CYBERPUNK
        )
    }

    fun activateMilitaryMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.MILITARY
        )
    }

    fun activateAccessibilityMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.ACCESSIBILITY
        )
    }

    fun activateLightMode() {

        SentriXThemeState.updateTheme(
            SentriXThemeMode.LIGHT
        )
    }
}



/* =========================================================
   ADVANCED THEME UTILITIES
   ========================================================= */

object ThemeUtilities {

    fun isDarkTheme(): Boolean {

        return SentriXThemeState.currentTheme !=
                SentriXThemeMode.LIGHT
    }

    fun isAMOLED(): Boolean {

        return SentriXThemeState.currentTheme ==
                SentriXThemeMode.AMOLED
    }

    fun isCyberpunk(): Boolean {

        return SentriXThemeState.currentTheme ==
                SentriXThemeMode.CYBERPUNK
    }

    fun isMilitary(): Boolean {

        return SentriXThemeState.currentTheme ==
                SentriXThemeMode.MILITARY
    }

    fun isAccessibility(): Boolean {

        return SentriXThemeState.currentTheme ==
                SentriXThemeMode.ACCESSIBILITY
    }
}



/* =========================================================
   FUTURE THEME ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Runtime enterprise branding
| ✔ AI adaptive themes
| ✔ Live gradient rendering
| ✔ Dynamic effect engine
| ✔ Cloud synchronized themes
| ✔ User custom themes
| ✔ Time-based themes
| ✔ Threat adaptive UI
| ✔ VR/AR rendering themes
| ✔ Holographic system themes
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX MAIN THEME ENGINE
|--------------------------------------------------------------------------
*/
