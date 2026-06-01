package com.sentrix.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX SCAN ANIMATION VIEW
|--------------------------------------------------------------------------
|
| PURPOSE:
| Advanced AI cybersecurity scanning visualization component.
|
| FEATURES:
|
| ✔ AI Scanner Animation
| ✔ Radar Sweep Effect
| ✔ Threat Detection Pulse
| ✔ Cyber Grid Rendering
| ✔ Rotating Scanner Beam
| ✔ Neural Visualization
| ✔ Holographic Effects
| ✔ Live System Analysis UI
| ✔ AMOLED Optimized
| ✔ Cyberpunk Compatible
| ✔ Enterprise Dashboard Ready
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| ScanAnimationView(
|     scanning = true,
|     scanProgress = 82
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SCAN STATES
   ========================================================= */

enum class ScanState {

    IDLE,

    SCANNING,

    ANALYZING,

    THREAT_DETECTED,

    SECURE
}



/* =========================================================
   SCAN STATUS MODEL
   ========================================================= */

data class ScanStatusData(

    val label: String,

    val color: Color
)



/* =========================================================
   SCAN STATUS ENGINE
   ========================================================= */

object ScanStatusEngine {

    fun status(
        state: ScanState
    ): ScanStatusData {

        return when (state) {

            ScanState.IDLE ->
                ScanStatusData(

                    label = "Idle",

                    color = Text_Muted
                )

            ScanState.SCANNING ->
                ScanStatusData(

                    label = "Scanning",

                    color = AI_Active
                )

            ScanState.ANALYZING ->
                ScanStatusData(

                    label = "Analyzing",

                    color = SentriX_AccentPurple
                )

            ScanState.THREAT_DETECTED ->
                ScanStatusData(

                    label = "Threat Detected",

                    color = Threat_Critical
                )

            ScanState.SECURE ->
                ScanStatusData(

                    label = "System Secure",

                    color = Threat_Low
                )
        }
    }
}



/* =========================================================
   MAIN SCAN ANIMATION VIEW
   ========================================================= */

@Composable
fun ScanAnimationView(

    modifier: Modifier = Modifier,

    scanning: Boolean = true,

    scanProgress: Int = 0,

    scanState: ScanState =
        ScanState.SCANNING,

    size: Int = 320,

    showCyberGrid: Boolean = true,

    showScannerBeam: Boolean = true,

    enablePulseEffect: Boolean = true
) {

    val statusData =
        ScanStatusEngine.status(
            scanState
        )



    /*
    |--------------------------------------------------------------------------
    | INFINITE TRANSITIONS
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | ROTATING RADAR SWEEP
    |--------------------------------------------------------------------------
    */

    val radarRotation by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 360f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 5000,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | INNER RING ROTATION
    |--------------------------------------------------------------------------
    */

    val innerRotation by infiniteTransition
        .animateFloat(

            initialValue = 360f,

            targetValue = 0f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 9000,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE ALPHA
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.25f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED PROGRESS
    |--------------------------------------------------------------------------
    */

    val animatedProgress by animateFloatAsState(

        targetValue = scanProgress / 100f,

        animationSpec = tween(

            durationMillis = 1400
        )
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Box(

        modifier = modifier
            .size(size.dp)
            .shadow(

                elevation =
                    SentriXShadow.Huge,

                shape =
                    CircleShape,

                ambientColor =
                    statusData.color.copy(
                        alpha = pulseAlpha
                    ),

                spotColor =
                    statusData.color.copy(
                        alpha = pulseAlpha
                    )
            )
            .clip(CircleShape)
            .background(
                color = Background_Main
            )
            .border(

                width = 1.2.dp,

                color =
                    statusData.color.copy(
                        alpha = 0.28f
                    ),

                shape =
                    CircleShape
            ),

        contentAlignment =
            Alignment.Center
    ) {

        /*
        |--------------------------------------------------------------------------
        | CYBER GRID BACKGROUND
        |--------------------------------------------------------------------------
        */

        if (showCyberGrid) {

            Canvas(

                modifier = Modifier
                    .matchParentSize()
                    .alpha(0.08f)
            ) {

                val spacing = 32.dp.toPx()

                for (
                    x in 0..size step 32
                ) {

                    drawLine(

                        color =
                            statusData.color,

                        start =
                            Offset(
                                x.toFloat(),
                                0f
                            ),

                        end =
                            Offset(
                                x.toFloat(),
                                size.toFloat()
                            ),

                        strokeWidth = 1f
                    )
                }

                for (
                    y in 0..size step 32
                ) {

                    drawLine(

                        color =
                            statusData.color,

                        start =
                            Offset(
                                0f,
                                y.toFloat()
                            ),

                        end =
                            Offset(
                                size.toFloat(),
                                y.toFloat()
                            ),

                        strokeWidth = 1f
                    )
                }
            }
        }



        /*
        |--------------------------------------------------------------------------
        | RADAR CANVAS
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
                .padding(18.dp)
        ) {

            val canvasSize =
                size.minDimension

            val radius =
                canvasSize / 2



            /*
            |--------------------------------------------------------------------------
            | OUTER RING
            |--------------------------------------------------------------------------
            */

            drawCircle(

                color =
                    statusData.color.copy(
                        alpha = 0.16f
                    ),

                radius =
                    radius - 20f,

                style = Stroke(
                    width = 6f
                )
            )



            /*
            |--------------------------------------------------------------------------
            | INNER RINGS
            |--------------------------------------------------------------------------
            */

            drawCircle(

                color =
                    statusData.color.copy(
                        alpha = 0.12f
                    ),

                radius =
                    radius - 70f,

                style = Stroke(
                    width = 4f
                )
            )

            drawCircle(

                color =
                    statusData.color.copy(
                        alpha = 0.08f
                    ),

                radius =
                    radius - 120f,

                style = Stroke(
                    width = 3f
                )
            )



            /*
            |--------------------------------------------------------------------------
            | PROGRESS ARC
            |--------------------------------------------------------------------------
            */

            drawArc(

                brush =
                    Brush.sweepGradient(

                        colors = listOf(

                            statusData.color,

                            Color.Transparent
                        )
                    ),

                startAngle = -90f,

                sweepAngle =
                    animatedProgress * 360f,

                useCenter = false,

                style = Stroke(

                    width = 14f,

                    cap = StrokeCap.Round
                ),

                size = Size(
                    canvasSize,
                    canvasSize
                )
            )



            /*
            |--------------------------------------------------------------------------
            | RADAR SWEEP
            |--------------------------------------------------------------------------
            */

            if (showScannerBeam) {

                rotate(radarRotation) {

                    drawLine(

                        brush =
                            Brush.linearGradient(

                                colors = listOf(

                                    Color.Transparent,

                                    statusData.color.copy(
                                        alpha = 0.9f
                                    )
                                )
                            ),

                        start = center,

                        end = Offset(
                            center.x,
                            0f
                        ),

                        strokeWidth = 8f
                    )
                }
            }



            /*
            |--------------------------------------------------------------------------
            | INNER ROTATION EFFECT
            |--------------------------------------------------------------------------
            */

            rotate(innerRotation) {

                drawArc(

                    color =
                        statusData.color.copy(
                            alpha = 0.3f
                        ),

                    startAngle = 0f,

                    sweepAngle = 120f,

                    useCenter = false,

                    style = Stroke(
                        width = 5f
                    ),

                    size = Size(
                        canvasSize - 120f,
                        canvasSize - 120f
                    ),

                    topLeft = Offset(
                        60f,
                        60f
                    )
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | CENTER CONTENT
        |--------------------------------------------------------------------------
        */

        Column(

            horizontalAlignment =
                Alignment.CenterHorizontally
        ) {

            /*
            |--------------------------------------------------------------------------
            | AI CORE ICON
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(88.dp)
                    .shadow(

                        elevation =
                            SentriXShadow.Large,

                        shape =
                            CircleShape,

                        ambientColor =
                            statusData.color
                                .copy(
                                    alpha = pulseAlpha
                                )
                    )
                    .clip(CircleShape)
                    .background(

                        brush =
                            AIGradients.Neural
                    )
                    .border(

                        width = 1.5.dp,

                        color =
                            statusData.color,

                        shape =
                            CircleShape
                    ),

                contentAlignment =
                    Alignment.Center
            ) {

                Icon(

                    imageVector = if (

                        scanState ==
                        ScanState.THREAT_DETECTED

                    )

                        Icons.Default.Security

                    else

                        Icons.Default.Memory,

                    contentDescription = null,

                    tint = Text_Primary,

                    modifier = Modifier.size(
                        IconDimensions.Huge
                    )
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraLarge
                )
            )



            /*
            |--------------------------------------------------------------------------
            | PROGRESS VALUE
            |--------------------------------------------------------------------------
            */

            Text(

                text = "$scanProgress%",

                style =
                    DashboardTypography.Metric,

                color =
                    Text_Primary,

                fontWeight =
                    FontWeight.ExtraBold
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )



            /*
            |--------------------------------------------------------------------------
            | STATUS LABEL
            |--------------------------------------------------------------------------
            */

            Text(

                text =
                    statusData.label,

                style =
                    SecurityTypography
                        .ThreatWarning,

                color =
                    statusData.color
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraSmall
                )
            )



            /*
            |--------------------------------------------------------------------------
            | SYSTEM MESSAGE
            |--------------------------------------------------------------------------
            */

            Text(

                text =
                    "Neural engine analyzing system activity",

                style =
                    AIScannerText,

                color =
                    Text_Secondary
            )



            /*
            |--------------------------------------------------------------------------
            | LIVE PULSE INDICATOR
            |--------------------------------------------------------------------------
            */

            if (
                enablePulseEffect
            ) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Large
                    )
                )

                Row(

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    Box(

                        modifier = Modifier
                            .size(10.dp)
                            .alpha(
                                pulseAlpha
                            )
                            .clip(
                                CircleShape
                            )
                            .background(
                                statusData.color
                            )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )

                    Text(

                        text =
                            "LIVE SCAN ACTIVE",

                        style =
                            TerminalTypography.Body,

                        color =
                            statusData.color
                    )
                }
            }
        }
    }
}



/* =========================================================
   MINI SCAN VIEW
   ========================================================= */

@Composable
fun MiniScanAnimationView(

    scanProgress: Int
) {

    ScanAnimationView(

        scanProgress = scanProgress,

        size = 180,

        showCyberGrid = false
    )
}



/* =========================================================
   THREAT DETECTION VIEW
   ========================================================= */

@Composable
fun ThreatDetectionView(

    threatScore: Int
) {

    ScanAnimationView(

        scanProgress = threatScore,

        scanState =
            ScanState.THREAT_DETECTED,

        showScannerBeam = true
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
| ✔ GPU accelerated radar rendering
| ✔ 3D holographic scanning
| ✔ AI adaptive scan engine
| ✔ Live attack visualization
| ✔ Dynamic threat clustering
| ✔ Runtime cyber-grid engine
| ✔ Quantum security analytics
| ✔ VR/AR scan rendering
| ✔ Interactive neural visualizer
| ✔ Real-time global attack map
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX SCAN ANIMATION VIEW
|--------------------------------------------------------------------------
*/
