package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX RING PULSE ANIMATION
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic pulse-ring visualization engine for SentriX.
|
| FEATURES:
|
| ✔ Multi-Layer Ring Pulse Effects
| ✔ AI Reactive Pulse System
| ✔ Threat Detection Visualization
| ✔ Cyberpunk Compatible
| ✔ Neon Glow Rendering
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Animations
| ✔ Enterprise Animation Framework
| ✔ Dynamic Pulse Waves
| ✔ Expandable Pulse Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| RingPulseAnimation(
|     pulseType = RingPulseType.AI
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   PULSE TYPES
   ========================================================= */

enum class RingPulseType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK,

    SUCCESS
}



/* =========================================================
   RING STYLE MODEL
   ========================================================= */

data class RingPulseStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color
)



/* =========================================================
   RING STYLE ENGINE
   ========================================================= */

object RingPulseEngine {

    fun style(
        type: RingPulseType
    ): RingPulseStyle {

        return when (type) {

            RingPulseType.DEFAULT ->

                RingPulseStyle(

                    primaryColor =
                        SentriX_AccentBlue,

                    secondaryColor =
                        SentriX_AccentCyan,

                    glowColor =
                        SentriX_AccentBlue
                )

            RingPulseType.SECURITY ->

                RingPulseStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    glowColor =
                        Threat_Low
                )

            RingPulseType.AI ->

                RingPulseStyle(

                    primaryColor =
                        AI_Active,

                    secondaryColor =
                        SentriX_AccentPurple,

                    glowColor =
                        AI_Active
                )

            RingPulseType.NETWORK ->

                RingPulseStyle(

                    primaryColor =
                        Network_Incoming,

                    secondaryColor =
                        SentriX_AccentBlue,

                    glowColor =
                        Network_Incoming
                )

            RingPulseType.THREAT ->

                RingPulseStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Threat_High,

                    glowColor =
                        Threat_Critical
                )

            RingPulseType.CYBERPUNK ->

                RingPulseStyle(

                    primaryColor =
                        Color(0xFFFF00FF),

                    secondaryColor =
                        Color(0xFF00FFFF),

                    glowColor =
                        Color(0xFFFF00FF)
                )

            RingPulseType.SUCCESS ->

                RingPulseStyle(

                    primaryColor =
                        Color(0xFF00E676),

                    secondaryColor =
                        Color(0xFF00C853),

                    glowColor =
                        Color(0xFF00E676)
                )
        }
    }
}



/* =========================================================
   MAIN RING PULSE ANIMATION
   ========================================================= */

@Composable
fun RingPulseAnimation(

    modifier: Modifier = Modifier,

    pulseType: RingPulseType =
        RingPulseType.DEFAULT,

    animationSize: Int = 220,

    ringThickness: Float = 8f,

    pulseDuration: Int = 2200,

    enableCoreGlow: Boolean = true,

    enableOuterPulse: Boolean = true,

    enableMultiRing: Boolean = true
) {

    val style =
        RingPulseEngine.style(
            pulseType
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | FIRST RING SCALE
    |--------------------------------------------------------------------------
    */

    val ringOneScale by infiniteTransition
        .animateFloat(

            initialValue = 0.45f,

            targetValue = 1.4f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            pulseDuration,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SECOND RING SCALE
    |--------------------------------------------------------------------------
    */

    val ringTwoScale by infiniteTransition
        .animateFloat(

            initialValue = 0.25f,

            targetValue = 1.2f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            pulseDuration + 500,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | THIRD RING SCALE
    |--------------------------------------------------------------------------
    */

    val ringThreeScale by infiniteTransition
        .animateFloat(

            initialValue = 0.15f,

            targetValue = 1.0f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            pulseDuration + 900,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | CORE PULSE
    |--------------------------------------------------------------------------
    */

    val coreAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.3f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1100),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | CORE SCALE
    |--------------------------------------------------------------------------
    */

    val coreScale by infiniteTransition
        .animateFloat(

            initialValue = 0.92f,

            targetValue = 1.08f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Box(

        modifier = modifier
            .size(animationSize.dp),

        contentAlignment =
            Alignment.Center
    ) {

        /*
        |--------------------------------------------------------------------------
        | OUTER GLOW
        |--------------------------------------------------------------------------
        */

        if (enableOuterPulse) {

            Box(

                modifier = Modifier
                    .size(
                        (animationSize * ringOneScale).dp
                    )
                    .alpha(

                        1f - (
                            ringOneScale / 1.5f
                        )
                    )
                    .blur(24.dp)
                    .clip(
                        CircleShape
                    )
                    .alpha(0.18f)
                    .background(
                        style.glowColor
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | FIRST RING
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .size(
                    (animationSize * ringOneScale).dp
                )
                .alpha(

                    1f - (
                        ringOneScale / 1.4f
                    )
                )
        ) {

            drawCircle(

                brush =
                    Brush.radialGradient(

                        colors = listOf(

                            style.secondaryColor,

                            style.primaryColor
                        )
                    ),

                style = Stroke(
                    width = ringThickness
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | SECOND RING
        |--------------------------------------------------------------------------
        */

        if (enableMultiRing) {

            Canvas(

                modifier = Modifier
                    .size(
                        (animationSize * ringTwoScale).dp
                    )
                    .alpha(

                        1f - (
                            ringTwoScale / 1.3f
                        )
                    )
            ) {

                drawCircle(

                    color =
                        style.primaryColor,

                    style = Stroke(
                        width = ringThickness * 0.7f
                    )
                )
            }



            /*
            ------------------------------------------------------------
            | THIRD RING
            ------------------------------------------------------------
            */

            Canvas(

                modifier = Modifier
                    .size(
                        (animationSize * ringThreeScale).dp
                    )
                    .alpha(

                        1f - (
                            ringThreeScale / 1.2f
                        )
                    )
            ) {

                drawCircle(

                    color =
                        style.secondaryColor,

                    style = Stroke(
                        width = ringThickness * 0.5f
                    )
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | CENTER CORE GLOW
        |--------------------------------------------------------------------------
        */

        if (enableCoreGlow) {

            Box(

                modifier = Modifier
                    .size(110.dp)
                    .alpha(
                        coreAlpha * 0.35f
                    )
                    .blur(22.dp)
                    .clip(
                        CircleShape
                    )
                    .background(
                        style.glowColor
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | MAIN CORE
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(
                    (84 * coreScale).dp
                )
                .clip(
                    CircleShape
                )
                .background(

                    brush =
                        Brush.radialGradient(

                            colors = listOf(

                                style.secondaryColor,

                                style.primaryColor
                            )
                        )
                ),

            contentAlignment =
                Alignment.Center
        ) {

            /*
            |--------------------------------------------------------------------------
            | INNER CORE
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(38.dp)
                    .alpha(
                        coreAlpha
                    )
                    .clip(
                        CircleShape
                    )
                    .background(
                        Color.White.copy(
                            alpha = 0.9f
                        )
                    )
            )
        }
    }
}



/* =========================================================
   AI RING PULSE
   ========================================================= */

@Composable
fun AIRingPulse(

    modifier: Modifier = Modifier
) {

    RingPulseAnimation(

        modifier = modifier,

        pulseType =
            RingPulseType.AI
    )
}



/* =========================================================
   SECURITY RING PULSE
   ========================================================= */

@Composable
fun SecurityRingPulse(

    modifier: Modifier = Modifier
) {

    RingPulseAnimation(

        modifier = modifier,

        pulseType =
            RingPulseType.SECURITY
    )
}



/* =========================================================
   THREAT RING PULSE
   ========================================================= */

@Composable
fun ThreatRingPulse(

    modifier: Modifier = Modifier
) {

    RingPulseAnimation(

        modifier = modifier,

        pulseType =
            RingPulseType.THREAT,

        pulseDuration = 1100
    )
}



/* =========================================================
   CYBERPUNK RING PULSE
   ========================================================= */

@Composable
fun CyberpunkRingPulse(

    modifier: Modifier = Modifier
) {

    RingPulseAnimation(

        modifier = modifier,

        pulseType =
            RingPulseType.CYBERPUNK
    )
}



/* =========================================================
   MINI RING PULSE
   ========================================================= */

@Composable
fun MiniRingPulse(

    modifier: Modifier = Modifier
) {

    RingPulseAnimation(

        modifier = modifier,

        animationSize = 80,

        ringThickness = 4f,

        enableMultiRing = false
    )
}



/* =========================================================
   FUTURE RING ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive pulse intelligence
| ✔ GPU accelerated pulse rendering
| ✔ Quantum ring framework
| ✔ Dynamic threat pulse system
| ✔ VR/AR pulse visualization
| ✔ Neural signal rendering
| ✔ Holographic pulse engine
| ✔ Runtime pulse synchronization
| ✔ Multi-layer cyber pulse system
| ✔ Global threat heartbeat engine
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX RING PULSE ANIMATION
|--------------------------------------------------------------------------
*/
