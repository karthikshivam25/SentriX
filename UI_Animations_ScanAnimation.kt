package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
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
| SENTRIX SCAN ANIMATION ENGINE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic scanning animation framework for SentriX.
|
| FEATURES:
|
| ✔ Radar Scan Animation
| ✔ AI Threat Scanner
| ✔ Rotating Sweep Effects
| ✔ Neon Glow Rendering
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Performance Optimized
| ✔ Enterprise Animation System
| ✔ Real-Time Monitoring Visuals
| ✔ Expandable Scan Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| ScanAnimation(
|     scanType = ScanAnimationType.AI
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SCAN TYPES
   ========================================================= */

enum class ScanAnimationType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK
}



/* =========================================================
   SCAN STYLE MODEL
   ========================================================= */

data class ScanAnimationStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color,

    val sweepBrush: Brush
)



/* =========================================================
   SCAN STYLE ENGINE
   ========================================================= */

object ScanAnimationEngine {

    fun style(
        type: ScanAnimationType
    ): ScanAnimationStyle {

        return when (type) {

            ScanAnimationType.DEFAULT ->

                ScanAnimationStyle(

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

            ScanAnimationType.SECURITY ->

                ScanAnimationStyle(

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

            ScanAnimationType.AI ->

                ScanAnimationStyle(

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

            ScanAnimationType.NETWORK ->

                ScanAnimationStyle(

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

            ScanAnimationType.THREAT ->

                ScanAnimationStyle(

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

            ScanAnimationType.CYBERPUNK ->

                ScanAnimationStyle(

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
        }
    }
}



/* =========================================================
   MAIN SCAN ANIMATION
   ========================================================= */

@Composable
fun ScanAnimation(

    modifier: Modifier = Modifier,

    scanType: ScanAnimationType =
        ScanAnimationType.DEFAULT,

    animationSize: Int = 220,

    scannerThickness: Float = 12f,

    enablePulseCore: Boolean = true,

    enableGrid: Boolean = true
) {

    val style =
        ScanAnimationEngine.style(
            scanType
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

                        durationMillis = 4200,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.25f,

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
    | FLOATING CORE
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -3f,

            targetValue = 3f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SCALE WAVE
    |--------------------------------------------------------------------------
    */

    val scaleWave by infiniteTransition
        .animateFloat(

            initialValue = 0.8f,

            targetValue = 1.3f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 2200,

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
        | GRID BACKGROUND
        |--------------------------------------------------------------------------
        */

        if (enableGrid) {

            Canvas(

                modifier = Modifier
                    .fillMaxSize()
                    .alpha(0.08f)
            ) {

                val spacing = 28f

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
        | OUTER PULSE WAVE
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(
                    (animationSize * scaleWave).dp
                )
                .alpha(
                    1f - (
                        scaleWave - 0.8f
                    )
                )
                .blur(16.dp)
                .clip(
                    CircleShape
                )
                .alpha(0.12f)
                .background(
                    style.glowColor
                )
        )



        /*
        |--------------------------------------------------------------------------
        | RADAR SCANNER
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

                sweepAngle = 95f,

                useCenter = false,

                style = Stroke(
                    width = scannerThickness
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | SCAN RINGS
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
                        alpha = 0.14f
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
                        alpha = 0.10f
                    ),

                radius =
                    size.minDimension / 4.8f,

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
                    floatingOffset * 3
                )
                .size(82.dp)
                .blur(0.2.dp)
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
                        .size(46.dp)
                        .alpha(
                            pulseAlpha
                        )
                        .clip(
                            CircleShape
                        )
                        .background(
                            Color.White.copy(
                                alpha = 0.85f
                            )
                        )
                )
            }
        }
    }
}



/* =========================================================
   AI SCAN ANIMATION
   ========================================================= */

@Composable
fun AIScanAnimation(

    modifier: Modifier = Modifier
) {

    ScanAnimation(

        modifier = modifier,

        scanType =
            ScanAnimationType.AI
    )
}



/* =========================================================
   SECURITY SCAN ANIMATION
   ========================================================= */

@Composable
fun SecurityScanAnimation(

    modifier: Modifier = Modifier
) {

    ScanAnimation(

        modifier = modifier,

        scanType =
            ScanAnimationType.SECURITY
    )
}



/* =========================================================
   THREAT SCAN ANIMATION
   ========================================================= */

@Composable
fun ThreatScanAnimation(

    modifier: Modifier = Modifier
) {

    ScanAnimation(

        modifier = modifier,

        scanType =
            ScanAnimationType.THREAT
    )
}



/* =========================================================
   MINI SCAN ANIMATION
   ========================================================= */

@Composable
fun MiniScanAnimation(

    modifier: Modifier = Modifier
) {

    ScanAnimation(

        modifier = modifier,

        animationSize = 90,

        scannerThickness = 6f,

        enableGrid = false
    )
}



/* =========================================================
   FUTURE SCAN ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive scan engine
| ✔ GPU accelerated radar rendering
| ✔ Quantum security scanning
| ✔ Dynamic threat visualization
| ✔ VR/AR scan rendering
| ✔ Real-time packet scan overlays
| ✔ Runtime AI scan intelligence
| ✔ Neural activity visualization
| ✔ Holographic scan engine
| ✔ Multi-layer cyber-grid system
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX SCAN ANIMATION ENGINE
|--------------------------------------------------------------------------
*/
