package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp

/*
|--------------------------------------------------------------------------
| SENTRIX PULSE ANIMATION ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Advanced reusable pulse animation engine for SentriX.
|
| FEATURES:
|
| ✔ Smooth Infinite Pulse Animations
| ✔ Cyberpunk Compatible
| ✔ AI Reactive Pulsing
| ✔ Neon Glow Support
| ✔ Performance Optimized
| ✔ AMOLED Ready
| ✔ Reusable Animation APIs
| ✔ Enterprise Animation Architecture
| ✔ Runtime Adaptive Motion
| ✔ Expandable Animation Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| val pulse =
|     rememberPulseAnimation()
|
| Modifier.graphicsLayer {
|     scaleX = pulse.scale
|     scaleY = pulse.scale
|     alpha = pulse.alpha
| }
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   PULSE MODES
   ========================================================= */

enum class PulseAnimationMode {

    SOFT,

    MEDIUM,

    AGGRESSIVE,

    AI,

    DANGER,

    CYBERPUNK
}



/* =========================================================
   PULSE STATE MODEL
   ========================================================= */

data class PulseAnimationState(

    val scale: Float,

    val alpha: Float,

    val glowAlpha: Float,

    val blurRadius: Float
)



/* =========================================================
   MAIN PULSE ENGINE
   ========================================================= */

@Composable
fun rememberPulseAnimation(

    mode: PulseAnimationMode =
        PulseAnimationMode.MEDIUM,

    enabled: Boolean = true
): PulseAnimationState {

    /*
    |--------------------------------------------------------------------------
    | MODE CONFIGURATION
    |--------------------------------------------------------------------------
    */

    val animationSpeed =
        when (mode) {

            PulseAnimationMode.SOFT ->
                2200

            PulseAnimationMode.MEDIUM ->
                1500

            PulseAnimationMode.AGGRESSIVE ->
                850

            PulseAnimationMode.AI ->
                1300

            PulseAnimationMode.DANGER ->
                650

            PulseAnimationMode.CYBERPUNK ->
                1000
        }



    val maxScale =
        when (mode) {

            PulseAnimationMode.SOFT ->
                1.03f

            PulseAnimationMode.MEDIUM ->
                1.06f

            PulseAnimationMode.AGGRESSIVE ->
                1.12f

            PulseAnimationMode.AI ->
                1.08f

            PulseAnimationMode.DANGER ->
                1.15f

            PulseAnimationMode.CYBERPUNK ->
                1.10f
        }



    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | SCALE ANIMATION
    |--------------------------------------------------------------------------
    */

    val scale by infiniteTransition
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
    | ALPHA ANIMATION
    |--------------------------------------------------------------------------
    */

    val alpha by infiniteTransition
        .animateFloat(

            initialValue = 0.78f,

            targetValue = if (enabled)

                1f

            else

                0.78f,

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
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.18f,

            targetValue = if (enabled)

                0.45f

            else

                0.18f,

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
    | BLUR ANIMATION
    |--------------------------------------------------------------------------
    */

    val blurRadius by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = if (enabled)

                4f

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

        scale,
        alpha,
        glowAlpha,
        blurRadius
    ) {

        PulseAnimationState(

            scale = scale,

            alpha = alpha,

            glowAlpha = glowAlpha,

            blurRadius = blurRadius
        )
    }
}



/* =========================================================
   QUICK PULSE MODIFIER
   ========================================================= */

fun Modifier.sentriXPulse(

    state: PulseAnimationState
): Modifier {

    return this
        .graphicsLayer {

            scaleX = state.scale

            scaleY = state.scale

            alpha = state.alpha
        }
        .blur(
            state.blurRadius.dp
        )
}



/* =========================================================
   AI PULSE PRESET
   ========================================================= */

@Composable
fun rememberAIPulseAnimation():

        PulseAnimationState {

    return rememberPulseAnimation(

        mode =
            PulseAnimationMode.AI
    )
}



/* =========================================================
   DANGER PULSE PRESET
   ========================================================= */

@Composable
fun rememberDangerPulseAnimation():

        PulseAnimationState {

    return rememberPulseAnimation(

        mode =
            PulseAnimationMode.DANGER
    )
}



/* =========================================================
   CYBERPUNK PULSE PRESET
   ========================================================= */

@Composable
fun rememberCyberpunkPulseAnimation():

        PulseAnimationState {

    return rememberPulseAnimation(

        mode =
            PulseAnimationMode.CYBERPUNK
    )
}



/* =========================================================
   SOFT UI PULSE PRESET
   ========================================================= */

@Composable
fun rememberSoftPulseAnimation():

        PulseAnimationState {

    return rememberPulseAnimation(

        mode =
            PulseAnimationMode.SOFT
    )
}



/* =========================================================
   FUTURE ANIMATION ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive motion engine
| ✔ GPU accelerated pulse rendering
| ✔ Runtime neural animation tuning
| ✔ Quantum animation framework
| ✔ Dynamic threat-reactive motion
| ✔ VR/AR animation synchronization
| ✔ Real-time motion intelligence
| ✔ Emotion-based animation engine
| ✔ System-performance adaptive FPS
| ✔ Cyber-grid pulse synchronization
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX PULSE ANIMATION ENGINE
|--------------------------------------------------------------------------
*/
