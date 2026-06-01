package com.sentrix.ui.animations

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX CYBER GRID ANIMATION
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic animated cyber-grid rendering engine for SentriX.
|
| FEATURES:
|
| ✔ Dynamic Cyber Grid Rendering
| ✔ Animated Neural Data Flow
| ✔ AI Reactive Grid Engine
| ✔ Cyberpunk Compatible
| ✔ Neon Line Effects
| ✔ AMOLED Optimized
| ✔ GPU-Friendly Rendering
| ✔ Enterprise Visualization Framework
| ✔ Real-Time Security Backgrounds
| ✔ Expandable Grid Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| CyberGridAnimation(
|     gridType = CyberGridType.AI
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   GRID TYPES
   ========================================================= */

enum class CyberGridType {

    DEFAULT,

    SECURITY,

    AI,

    NETWORK,

    THREAT,

    CYBERPUNK,

    QUANTUM
}



/* =========================================================
   GRID STYLE MODEL
   ========================================================= */

data class CyberGridStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val glowColor: Color,

    val pulseColor: Color
)



/* =========================================================
   GRID STYLE ENGINE
   ========================================================= */

object CyberGridEngine {

    fun style(
        type: CyberGridType
    ): CyberGridStyle {

        return when (type) {

            CyberGridType.DEFAULT ->

                CyberGridStyle(

                    primaryColor =
                        SentriX_AccentBlue,

                    secondaryColor =
                        SentriX_AccentCyan,

                    glowColor =
                        SentriX_AccentBlue,

                    pulseColor =
                        SentriX_AccentCyan
                )

            CyberGridType.SECURITY ->

                CyberGridStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    glowColor =
                        Threat_Low,

                    pulseColor =
                        SentriX_AccentGreen
                )

            CyberGridType.AI ->

                CyberGridStyle(

                    primaryColor =
                        AI_Active,

                    secondaryColor =
                        SentriX_AccentPurple,

                    glowColor =
                        AI_Active,

                    pulseColor =
                        SentriX_AccentPurple
                )

            CyberGridType.NETWORK ->

                CyberGridStyle(

                    primaryColor =
                        Network_Incoming,

                    secondaryColor =
                        SentriX_AccentBlue,

                    glowColor =
                        Network_Incoming,

                    pulseColor =
                        SentriX_AccentBlue
                )

            CyberGridType.THREAT ->

                CyberGridStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Threat_High,

                    glowColor =
                        Threat_Critical,

                    pulseColor =
                        Threat_High
                )

            CyberGridType.CYBERPUNK ->

                CyberGridStyle(

                    primaryColor =
                        Color(0xFFFF00FF),

                    secondaryColor =
                        Color(0xFF00FFFF),

                    glowColor =
                        Color(0xFFFF00FF),

                    pulseColor =
                        Color(0xFF00FFFF)
                )

            CyberGridType.QUANTUM ->

                CyberGridStyle(

                    primaryColor =
                        Color(0xFF7C4DFF),

                    secondaryColor =
                        Color(0xFF00E5FF),

                    glowColor =
                        Color(0xFF7C4DFF),

                    pulseColor =
                        Color(0xFF00E5FF)
                )
        }
    }
}



/* =========================================================
   MAIN CYBER GRID ANIMATION
   ========================================================= */

@Composable
fun CyberGridAnimation(

    modifier: Modifier = Modifier,

    gridType: CyberGridType =
        CyberGridType.DEFAULT,

    gridSpacing: Float = 42f,

    lineThickness: Float = 1f,

    pulseNodeSize: Float = 8f,

    animationSpeed: Int = 5000,

    enablePulseNodes: Boolean = true,

    enableGlow: Boolean = true,

    enableMovingWave: Boolean = true
) {

    val style =
        CyberGridEngine.style(
            gridType
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
    | WAVE MOVEMENT
    |--------------------------------------------------------------------------
    */

    val waveOffset by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 1000f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis =
                            animationSpeed,

                        easing =
                            LinearEasing
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

            initialValue = 0.15f,

            targetValue = 0.8f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GRID GLOW
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.04f,

            targetValue = 0.12f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2400),

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
            .fillMaxSize(),

        contentAlignment =
            Alignment.Center
    ) {

        /*
        |--------------------------------------------------------------------------
        | GLOW BACKGROUND
        |--------------------------------------------------------------------------
        */

        if (enableGlow) {

            Box(

                modifier = Modifier
                    .fillMaxSize()
                    .alpha(glowAlpha)
                    .blur(28.dp)
                    .background(
                        style.glowColor
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | CYBER GRID
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
        ) {

            /*
            ------------------------------------------------------------
            | VERTICAL LINES
            ------------------------------------------------------------
            */

            for (
                x in 0..size.width.toInt()
                        step gridSpacing.toInt()
            ) {

                drawLine(

                    color =
                        style.primaryColor.copy(
                            alpha = 0.16f
                        ),

                    start =
                        Offset(
                            x.toFloat(),
                            0f
                        ),

                    end =
                        Offset(
                            x.toFloat(),
                            size.height
                        ),

                    strokeWidth =
                        lineThickness
                )
            }



            /*
            ------------------------------------------------------------
            | HORIZONTAL LINES
            ------------------------------------------------------------
            */

            for (
                y in 0..size.height.toInt()
                        step gridSpacing.toInt()
            ) {

                drawLine(

                    color =
                        style.primaryColor.copy(
                            alpha = 0.16f
                        ),

                    start =
                        Offset(
                            0f,
                            y.toFloat()
                        ),

                    end =
                        Offset(
                            size.width,
                            y.toFloat()
                        ),

                    strokeWidth =
                        lineThickness
                )
            }



            /*
            ------------------------------------------------------------
            | MOVING WAVE
            ------------------------------------------------------------
            */

            if (enableMovingWave) {

                val animatedX =
                    waveOffset % size.width

                drawLine(

                    brush =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color.Transparent,

                                style.secondaryColor,

                                Color.Transparent
                            )
                        ),

                    start =
                        Offset(
                            animatedX,
                            0f
                        ),

                    end =
                        Offset(
                            animatedX,
                            size.height
                        ),

                    strokeWidth = 5f
                )
            }



            /*
            ------------------------------------------------------------
            | PULSE NODES
            ------------------------------------------------------------
            */

            if (enablePulseNodes) {

                for (
                    x in 0..size.width.toInt()
                            step (gridSpacing * 2).toInt()
                ) {

                    for (
                        y in 0..size.height.toInt()
                                step (gridSpacing * 2).toInt()
                    ) {

                        drawCircle(

                            color =
                                style.pulseColor.copy(
                                    alpha = pulseAlpha
                                ),

                            radius =
                                pulseNodeSize,

                            center =
                                Offset(
                                    x.toFloat(),
                                    y.toFloat()
                                )
                        )
                    }
                }
            }



            /*
            ------------------------------------------------------------
            | OUTER FRAME
            ------------------------------------------------------------
            */

            drawRect(

                color =
                    style.secondaryColor.copy(
                        alpha = 0.14f
                    ),

                style = Stroke(
                    width = 2f
                )
            )
        }
    }
}



/* =========================================================
   AI CYBER GRID
   ========================================================= */

@Composable
fun AICyberGrid(

    modifier: Modifier = Modifier
) {

    CyberGridAnimation(

        modifier = modifier,

        gridType =
            CyberGridType.AI
    )
}



/* =========================================================
   SECURITY CYBER GRID
   ========================================================= */

@Composable
fun SecurityCyberGrid(

    modifier: Modifier = Modifier
) {

    CyberGridAnimation(

        modifier = modifier,

        gridType =
            CyberGridType.SECURITY
    )
}



/* =========================================================
   THREAT CYBER GRID
   ========================================================= */

@Composable
fun ThreatCyberGrid(

    modifier: Modifier = Modifier
) {

    CyberGridAnimation(

        modifier = modifier,

        gridType =
            CyberGridType.THREAT,

        animationSpeed = 2400
    )
}



/* =========================================================
   CYBERPUNK GRID
   ========================================================= */

@Composable
fun CyberpunkGrid(

    modifier: Modifier = Modifier
) {

    CyberGridAnimation(

        modifier = modifier,

        gridType =
            CyberGridType.CYBERPUNK
    )
}



/* =========================================================
   MINI GRID
   ========================================================= */

@Composable
fun MiniCyberGrid(

    modifier: Modifier = Modifier
) {

    CyberGridAnimation(

        modifier = modifier,

        gridSpacing = 24f,

        pulseNodeSize = 4f,

        enableGlow = false
    )
}



/* =========================================================
   FUTURE GRID ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive grid rendering
| ✔ GPU accelerated cyber-grid engine
| ✔ Quantum visualization framework
| ✔ Dynamic threat heatmaps
| ✔ VR/AR background rendering
| ✔ Real-time packet visualization
| ✔ Neural data stream rendering
| ✔ Holographic grid projection
| ✔ Multi-layer cyber-grid engine
| ✔ Global threat visualization system
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX CYBER GRID ANIMATION
|--------------------------------------------------------------------------
*/
