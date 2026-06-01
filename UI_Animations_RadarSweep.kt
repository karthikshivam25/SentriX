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
| SENTRIX RADAR SWEEP ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic radar sweep visualization system for SentriX.
|
| FEATURES:
|
| ✔ Real-Time Radar Sweep Animation
| ✔ Threat Detection Visualization
| ✔ AI Monitoring Scanner
| ✔ Neon Sweep Rendering
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Rendering
| ✔ Enterprise Animation Architecture
| ✔ Multi-Layer Sweep Engine
| ✔ Expandable Radar Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| RadarSweep(
|     radarType = RadarSweepType.SECURITY
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   RADAR TYPES
   ========================================================= */

enum class RadarSweepType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK,

    QUANTUM
}



/* =========================================================
   RADAR STYLE MODEL
   ========================================================= */

data class RadarSweepStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color,

    val sweepBrush: Brush
)



/* =========================================================
   RADAR STYLE ENGINE
   ========================================================= */

object RadarSweepEngine {

    fun style(
        type: RadarSweepType
    ): RadarSweepStyle {

        return when (type) {

            RadarSweepType.DEFAULT ->

                RadarSweepStyle(

                    primaryColor =
                        SentriX_AccentBlue,

                    secondaryColor =
                        SentriX_AccentCyan,

                    glowColor =
                        SentriX_AccentBlue,

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                SentriX_AccentBlue,

                                SentriX_AccentCyan,

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.SECURITY ->

                RadarSweepStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    glowColor =
                        Threat_Low,

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_Low,

                                SentriX_AccentGreen,

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.AI ->

                RadarSweepStyle(

                    primaryColor =
                        AI_Active,

                    secondaryColor =
                        SentriX_AccentPurple,

                    glowColor =
                        AI_Active,

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                AI_Active,

                                SentriX_AccentPurple,

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.NETWORK ->

                RadarSweepStyle(

                    primaryColor =
                        Network_Incoming,

                    secondaryColor =
                        SentriX_AccentBlue,

                    glowColor =
                        Network_Incoming,

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Network_Incoming,

                                SentriX_AccentBlue,

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.THREAT ->

                RadarSweepStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Threat_High,

                    glowColor =
                        Threat_Critical,

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Threat_Critical,

                                Threat_High,

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.CYBERPUNK ->

                RadarSweepStyle(

                    primaryColor =
                        Color(0xFFFF00FF),

                    secondaryColor =
                        Color(0xFF00FFFF),

                    glowColor =
                        Color(0xFFFF00FF),

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Color(0xFFFF00FF),

                                Color(0xFF00FFFF),

                                Color.Transparent
                            )
                        )
                )

            RadarSweepType.QUANTUM ->

                RadarSweepStyle(

                    primaryColor =
                        Color(0xFF7C4DFF),

                    secondaryColor =
                        Color(0xFF00E5FF),

                    glowColor =
                        Color(0xFF7C4DFF),

                    sweepBrush =
                        Brush.sweepGradient(

                            colors = listOf(

                                Color.Transparent,

                                Color(0xFF7C4DFF),

                                Color(0xFF00E5FF),

                                Color.Transparent
                            )
                        )
                )
        }
    }
}



/* =========================================================
   MAIN RADAR SWEEP
   ========================================================= */

@Composable
fun RadarSweep(

    modifier: Modifier = Modifier,

    radarType: RadarSweepType =
        RadarSweepType.DEFAULT,

    radarSize: Int = 260,

    sweepThickness: Float = 12f,

    rotationDuration: Int = 4200,

    enablePulseCore: Boolean = true,

    enableGrid: Boolean = true,

    enableSweepGlow: Boolean = true
) {

    val style =
        RadarSweepEngine.style(
            radarType
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

    val radarRotation by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 360f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            rotationDuration,

                        easing =
                            LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE CORE
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.2f,

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
    | WAVE SCALE
    |--------------------------------------------------------------------------
    */

    val waveScale by infiniteTransition
        .animateFloat(

            initialValue = 0.7f,

            targetValue = 1.4f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 2400,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | FLOATING CORE
    |--------------------------------------------------------------------------
    */

    val floatingRotation by infiniteTransition
        .animateFloat(

            initialValue = -6f,

            targetValue = 6f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2600),

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
            .size(radarSize.dp),

        contentAlignment =
            Alignment.Center
    ) {

        /*
        |--------------------------------------------------------------------------
        | CYBER GRID
        |--------------------------------------------------------------------------
        */

        if (enableGrid) {

            Canvas(

                modifier = Modifier
                    .fillMaxSize()
                    .alpha(0.06f)
            ) {

                val spacing = 30f

                for (
                    x in 0..size.width.toInt()
                            step spacing.toInt()
                ) {

                    drawLine(

                        color =
                            style.primaryColor,

                        start =
                            androidx.compose.ui.geometry.Offset(
                                x.toFloat(),
                                0f
                            ),

                        end =
                            androidx.compose.ui.geometry.Offset(
                                x.toFloat(),
                                size.height
                            ),

                        strokeWidth = 1f
                    )
                }

                for (
                    y in 0..size.height.toInt()
                            step spacing.toInt()
                ) {

                    drawLine(

                        color =
                            style.primaryColor,

                        start =
                            androidx.compose.ui.geometry.Offset(
                                0f,
                                y.toFloat()
                            ),

                        end =
                            androidx.compose.ui.geometry.Offset(
                                size.width,
                                y.toFloat()
                            ),

                        strokeWidth = 1f
                    )
                }
            }
        }



        /*
        |--------------------------------------------------------------------------
        | OUTER WAVE
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(
                    (radarSize * waveScale).dp
                )
                .alpha(

                    1f - (
                        waveScale / 1.5f
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



        /*
        |--------------------------------------------------------------------------
        | RADAR SWEEP
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
                .rotate(
                    radarRotation
                )
        ) {

            drawArc(

                brush =
                    style.sweepBrush,

                startAngle = 0f,

                sweepAngle = 100f,

                useCenter = false,

                style = Stroke(
                    width = sweepThickness
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | SWEEP GLOW
        |--------------------------------------------------------------------------
        */

        if (enableSweepGlow) {

            Canvas(

                modifier = Modifier
                    .fillMaxSize()
                    .rotate(
                        radarRotation
                    )
                    .blur(10.dp)
                    .alpha(0.3f)
            ) {

                drawArc(

                    brush =
                        style.sweepBrush,

                    startAngle = 0f,

                    sweepAngle = 100f,

                    useCenter = false,

                    style = Stroke(
                        width = sweepThickness * 2
                    )
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | RADAR RINGS
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
        ) {

            drawCircle(

                color =
                    style.primaryColor.copy(
                        alpha = 0.18f
                    ),

                style = Stroke(
                    width = 2f
                )
            )

            drawCircle(

                color =
                    style.primaryColor.copy(
                        alpha = 0.12f
                    ),

                radius =
                    size.minDimension / 3f,

                style = Stroke(
                    width = 2f
                )
            )

            drawCircle(

                color =
                    style.primaryColor.copy(
                        alpha = 0.08f
                    ),

                radius =
                    size.minDimension / 4.5f,

                style = Stroke(
                    width = 2f
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | CENTER CORE
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .rotate(
                    floatingRotation
                )
                .size(90.dp)
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

            if (enablePulseCore) {

                Box(

                    modifier = Modifier
                        .size(42.dp)
                        .alpha(
                            pulseAlpha
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
}



/* =========================================================
   AI RADAR
   ========================================================= */

@Composable
fun AIRadarSweep(

    modifier: Modifier = Modifier
) {

    RadarSweep(

        modifier = modifier,

        radarType =
            RadarSweepType.AI
    )
}



/* =========================================================
   SECURITY RADAR
   ========================================================= */

@Composable
fun SecurityRadarSweep(

    modifier: Modifier = Modifier
) {

    RadarSweep(

        modifier = modifier,

        radarType =
            RadarSweepType.SECURITY
    )
}



/* =========================================================
   THREAT RADAR
   ========================================================= */

@Composable
fun ThreatRadarSweep(

    modifier: Modifier = Modifier
) {

    RadarSweep(

        modifier = modifier,

        radarType =
            RadarSweepType.THREAT,

        rotationDuration = 1800
    )
}



/* =========================================================
   CYBERPUNK RADAR
   ========================================================= */

@Composable
fun CyberpunkRadarSweep(

    modifier: Modifier = Modifier
) {

    RadarSweep(

        modifier = modifier,

        radarType =
            RadarSweepType.CYBERPUNK
    )
}



/* =========================================================
   MINI RADAR
   ========================================================= */

@Composable
fun MiniRadarSweep(

    modifier: Modifier = Modifier
) {

    RadarSweep(

        modifier = modifier,

        radarSize = 90,

        sweepThickness = 5f,

        enableGrid = false,

        enableSweepGlow = false
    )
}



/* =========================================================
   FUTURE RADAR ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive radar intelligence
| ✔ GPU accelerated radar rendering
| ✔ Quantum sweep engine
| ✔ Dynamic threat heatmaps
| ✔ VR/AR radar visualization
| ✔ Real-time packet scanning
| ✔ Neural tracking system
| ✔ Multi-layer radar analytics
| ✔ Holographic radar rendering
| ✔ Global threat synchronization
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX RADAR SWEEP ENGINE
|--------------------------------------------------------------------------
*/
