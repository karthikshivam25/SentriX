package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX THREAT DETECTED ANIMATION
|--------------------------------------------------------------------------
|
| PURPOSE:
| High-priority cyber threat visualization engine for SentriX.
|
| FEATURES:
|
| ✔ Critical Threat Pulse System
| ✔ AI Threat Warning Visualization
| ✔ Animated Alert Rings
| ✔ Cyberpunk Emergency Effects
| ✔ Live Threat Scanner
| ✔ AMOLED Optimized
| ✔ Enterprise Security Ready
| ✔ Dynamic Threat Rendering
| ✔ GPU-Friendly Animations
| ✔ Expandable Threat Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| ThreatDetectedAnimation()
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   THREAT LEVELS
   ========================================================= */

enum class ThreatAnimationLevel {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL,

    QUARANTINED
}



/* =========================================================
   THREAT STYLE MODEL
   ========================================================= */

data class ThreatAnimationStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color,

    val scannerBrush: Brush
)



/* =========================================================
   THREAT STYLE ENGINE
   ========================================================= */

object ThreatAnimationEngine {

    fun style(
        level: ThreatAnimationLevel
    ): ThreatAnimationStyle {

        return when (level) {

            ThreatAnimationLevel.LOW ->

                ThreatAnimationStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    glowColor =
                        Threat_Low,

                    scannerBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_Low,

                                SentriX_AccentGreen,

                                Color.Transparent
                            )
                        )
                )

            ThreatAnimationLevel.MEDIUM ->

                ThreatAnimationStyle(

                    primaryColor =
                        Threat_Medium,

                    secondaryColor =
                        Color(0xFFFFC107),

                    glowColor =
                        Threat_Medium,

                    scannerBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_Medium,

                                Color(0xFFFFC107),

                                Color.Transparent
                            )
                        )
                )

            ThreatAnimationLevel.HIGH ->

                ThreatAnimationStyle(

                    primaryColor =
                        Threat_High,

                    secondaryColor =
                        Color(0xFFFF7043),

                    glowColor =
                        Threat_High,

                    scannerBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_High,

                                Color(0xFFFF7043),

                                Color.Transparent
                            )
                        )
                )

            ThreatAnimationLevel.CRITICAL ->

                ThreatAnimationStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Color(0xFFFF1744),

                    glowColor =
                        Threat_Critical,

                    scannerBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_Critical,

                                Color(0xFFFF1744),

                                Color.Transparent
                            )
                        )
                )

            ThreatAnimationLevel.QUARANTINED ->

                ThreatAnimationStyle(

                    primaryColor =
                        SentriX_AccentPurple,

                    secondaryColor =
                        Color(0xFF7C4DFF),

                    glowColor =
                        SentriX_AccentPurple,

                    scannerBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                SentriX_AccentPurple,

                                Color(0xFF7C4DFF),

                                Color.Transparent
                            )
                        )
                )
        }
    }
}



/* =========================================================
   MAIN THREAT DETECTED ANIMATION
   ========================================================= */

@Composable
fun ThreatDetectedAnimation(

    modifier: Modifier = Modifier,

    threatLevel: ThreatAnimationLevel =
        ThreatAnimationLevel.CRITICAL,

    animationSize: Int = 240,

    enableEmergencyPulse: Boolean = true,

    enableScanner: Boolean = true,

    enableShockwave: Boolean = true
) {

    val style =
        ThreatAnimationEngine.style(
            threatLevel
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
    | RADAR ROTATION
    |--------------------------------------------------------------------------
    */

    val scannerRotation by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 360f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 1800,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ALERT PULSE
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.25f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(450),

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

                    animation = tween(600),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SHOCKWAVE EXPANSION
    |--------------------------------------------------------------------------
    */

    val shockwaveScale by infiniteTransition
        .animateFloat(

            initialValue = 0.6f,

            targetValue = 1.8f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 1800,

                        easing = LinearEasing
                    )
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
        | SHOCKWAVE EFFECT
        |--------------------------------------------------------------------------
        */

        if (enableShockwave) {

            Box(

                modifier = Modifier
                    .size(
                        (animationSize * shockwaveScale).dp
                    )
                    .alpha(

                        1f - (
                            shockwaveScale / 2f
                        )
                    )
                    .blur(18.dp)
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
        | OUTER ALERT RING
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
                .alpha(
                    pulseAlpha * 0.8f
                )
        ) {

            drawCircle(

                color =
                    style.primaryColor,

                style = Stroke(
                    width = 10f
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | INNER ALERT RING
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .size(
                    (animationSize * 0.72f).dp
                )
                .alpha(
                    pulseAlpha * 0.6f
                )
        ) {

            drawCircle(

                color =
                    style.secondaryColor,

                style = Stroke(
                    width = 8f
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | THREAT SCANNER
        |--------------------------------------------------------------------------
        */

        if (enableScanner) {

            Canvas(

                modifier = Modifier
                    .fillMaxSize()
                    .rotate(
                        scannerRotation
                    )
            ) {

                drawArc(

                    brush =
                        style.scannerBrush,

                    startAngle = 0f,

                    sweepAngle = 110f,

                    useCenter = false,

                    style = Stroke(
                        width = 14f
                    )
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | CORE GLOW
        |--------------------------------------------------------------------------
        */

        if (enableEmergencyPulse) {

            Box(

                modifier = Modifier
                    .size(120.dp)
                    .alpha(
                        pulseAlpha * 0.35f
                    )
                    .blur(28.dp)
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
                    (92 * coreScale).dp
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
                    .size(44.dp)
                    .alpha(
                        pulseAlpha
                    )
                    .clip(
                        CircleShape
                    )
                    .background(
                        Color.White.copy(
                            alpha = 0.92f
                        )
                    )
            )
        }
    }
}



/* =========================================================
   LOW THREAT ANIMATION
   ========================================================= */

@Composable
fun LowThreatAnimation(

    modifier: Modifier = Modifier
) {

    ThreatDetectedAnimation(

        modifier = modifier,

        threatLevel =
            ThreatAnimationLevel.LOW
    )
}



/* =========================================================
   HIGH THREAT ANIMATION
   ========================================================= */

@Composable
fun HighThreatAnimation(

    modifier: Modifier = Modifier
) {

    ThreatDetectedAnimation(

        modifier = modifier,

        threatLevel =
            ThreatAnimationLevel.HIGH
    )
}



/* =========================================================
   CRITICAL THREAT ANIMATION
   ========================================================= */

@Composable
fun CriticalThreatAnimation(

    modifier: Modifier = Modifier
) {

    ThreatDetectedAnimation(

        modifier = modifier,

        threatLevel =
            ThreatAnimationLevel.CRITICAL
    )
}



/* =========================================================
   QUARANTINE ANIMATION
   ========================================================= */

@Composable
fun QuarantineThreatAnimation(

    modifier: Modifier = Modifier
) {

    ThreatDetectedAnimation(

        modifier = modifier,

        threatLevel =
            ThreatAnimationLevel.QUARANTINED
    )
}



/* =========================================================
   MINI THREAT ANIMATION
   ========================================================= */

@Composable
fun MiniThreatAnimation(

    modifier: Modifier = Modifier
) {

    ThreatDetectedAnimation(

        modifier = modifier,

        animationSize = 90,

        enableShockwave = false
    )
}



/* =========================================================
   FUTURE THREAT ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive threat visualization
| ✔ GPU accelerated emergency rendering
| ✔ Quantum threat pulse engine
| ✔ Dynamic cyber-grid alerts
| ✔ VR/AR threat rendering
| ✔ Real-time malware visualization
| ✔ Runtime neural threat intelligence
| ✔ Holographic alert system
| ✔ Global threat synchronization
| ✔ Multi-layer attack visualization
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX THREAT DETECTED ANIMATION
|--------------------------------------------------------------------------
*/
