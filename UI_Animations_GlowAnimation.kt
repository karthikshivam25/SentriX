package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX GLOW ANIMATION ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Advanced reusable glow animation framework for SentriX.
|
| FEATURES:
|
| ✔ Dynamic Neon Glow Effects
| ✔ Cyberpunk Compatible
| ✔ AI Reactive Glow System
| ✔ Smooth Infinite Animations
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Rendering
| ✔ Reusable Modifier APIs
| ✔ Enterprise Animation Architecture
| ✔ Runtime Adaptive Motion
| ✔ Expandable Glow Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| val glow =
|     rememberGlowAnimation()
|
| Modifier.sentriXGlow(glow)
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   GLOW MODES
   ========================================================= */

enum class GlowAnimationMode {

    SOFT,

    MEDIUM,

    STRONG,

    AI,

    DANGER,

    CYBERPUNK,

    SUCCESS
}



/* =========================================================
   GLOW STATE MODEL
   ========================================================= */

data class GlowAnimationState(

    val glowAlpha: Float,

    val glowScale: Float,

    val blurRadius: Float,

    val glowColor: Color
)



/* =========================================================
   GLOW ENGINE
   ========================================================= */

@Composable
fun rememberGlowAnimation(

    mode: GlowAnimationMode =
        GlowAnimationMode.MEDIUM,

    enabled: Boolean = true
): GlowAnimationState {

    /*
    |--------------------------------------------------------------------------
    | MODE CONFIGURATION
    |--------------------------------------------------------------------------
    */

    val animationSpeed =
        when (mode) {

            GlowAnimationMode.SOFT ->
                2400

            GlowAnimationMode.MEDIUM ->
                1800

            GlowAnimationMode.STRONG ->
                1200

            GlowAnimationMode.AI ->
                1400

            GlowAnimationMode.DANGER ->
                700

            GlowAnimationMode.CYBERPUNK ->
                900

            GlowAnimationMode.SUCCESS ->
                1600
        }



    val maxGlowAlpha =
        when (mode) {

            GlowAnimationMode.SOFT ->
                0.18f

            GlowAnimationMode.MEDIUM ->
                0.35f

            GlowAnimationMode.STRONG ->
                0.55f

            GlowAnimationMode.AI ->
                0.45f

            GlowAnimationMode.DANGER ->
                0.75f

            GlowAnimationMode.CYBERPUNK ->
                0.65f

            GlowAnimationMode.SUCCESS ->
                0.30f
        }



    val maxScale =
        when (mode) {

            GlowAnimationMode.SOFT ->
                1.03f

            GlowAnimationMode.MEDIUM ->
                1.06f

            GlowAnimationMode.STRONG ->
                1.10f

            GlowAnimationMode.AI ->
                1.08f

            GlowAnimationMode.DANGER ->
                1.14f

            GlowAnimationMode.CYBERPUNK ->
                1.12f

            GlowAnimationMode.SUCCESS ->
                1.05f
        }



    val blurStrength =
        when (mode) {

            GlowAnimationMode.SOFT ->
                6f

            GlowAnimationMode.MEDIUM ->
                10f

            GlowAnimationMode.STRONG ->
                16f

            GlowAnimationMode.AI ->
                14f

            GlowAnimationMode.DANGER ->
                22f

            GlowAnimationMode.CYBERPUNK ->
                18f

            GlowAnimationMode.SUCCESS ->
                8f
        }



    val glowColor =
        when (mode) {

            GlowAnimationMode.SOFT ->
                SentriX_AccentBlue

            GlowAnimationMode.MEDIUM ->
                SentriX_AccentCyan

            GlowAnimationMode.STRONG ->
                SentriX_AccentPurple

            GlowAnimationMode.AI ->
                AI_Active

            GlowAnimationMode.DANGER ->
                Threat_Critical

            GlowAnimationMode.CYBERPUNK ->
                Color(0xFFFF00FF)

            GlowAnimationMode.SUCCESS ->
                Threat_Low
        }



    /*
    |--------------------------------------------------------------------------
    | ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | GLOW ALPHA
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.15f,

            targetValue = if (enabled)

                maxGlowAlpha

            else

                0.15f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            animationSpeed
                    ),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW SCALE
    |--------------------------------------------------------------------------
    */

    val glowScale by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = if (enabled)

                maxScale

            else

                1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            animationSpeed,

                        easing =
                            FastOutSlowInEasing
                    ),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | BLUR ANIMATION
    |--------------------------------------------------------------------------
    */

    val blurRadius by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = if (enabled)

                blurStrength

            else

                0f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            animationSpeed
                    ),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    return remember(

        glowAlpha,
        glowScale,
        blurRadius,
        glowColor
    ) {

        GlowAnimationState(

            glowAlpha = glowAlpha,

            glowScale = glowScale,

            blurRadius = blurRadius,

            glowColor = glowColor
        )
    }
}



/* =========================================================
   GLOW MODIFIER
   ========================================================= */

fun Modifier.sentriXGlow(

    glow: GlowAnimationState
): Modifier {

    return this
        .graphicsLayer {

            scaleX = glow.glowScale

            scaleY = glow.glowScale

            alpha = 1f
        }
        .blur(
            glow.blurRadius.dp
        )
}



/* =========================================================
   AI GLOW PRESET
   ========================================================= */

@Composable
fun rememberAIGlowAnimation():

        GlowAnimationState {

    return rememberGlowAnimation(

        mode =
            GlowAnimationMode.AI
    )
}



/* =========================================================
   DANGER GLOW PRESET
   ========================================================= */

@Composable
fun rememberDangerGlowAnimation():

        GlowAnimationState {

    return rememberGlowAnimation(

        mode =
            GlowAnimationMode.DANGER
    )
}



/* =========================================================
   CYBERPUNK GLOW PRESET
   ========================================================= */

@Composable
fun rememberCyberpunkGlowAnimation():

        GlowAnimationState {

    return rememberGlowAnimation(

        mode =
            GlowAnimationMode.CYBERPUNK
    )
}



/* =========================================================
   SUCCESS GLOW PRESET
   ========================================================= */

@Composable
fun rememberSuccessGlowAnimation():

        GlowAnimationState {

    return rememberGlowAnimation(

        mode =
            GlowAnimationMode.SUCCESS
    )
}



/* =========================================================
   FUTURE GLOW ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive glow rendering
| ✔ GPU accelerated neon engine
| ✔ Runtime light intelligence
| ✔ Quantum glow framework
| ✔ Dynamic cyber-grid illumination
| ✔ VR/AR lighting synchronization
| ✔ Real-time threat-reactive glow
| ✔ Holographic light rendering
| ✔ Neural visual enhancement
| ✔ Multi-layer lighting engine
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX GLOW ANIMATION ENGINE
|--------------------------------------------------------------------------
*/
