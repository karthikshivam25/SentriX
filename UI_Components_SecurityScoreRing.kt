package com.sentrix.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.VerifiedUser
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX SECURITY SCORE RING
|--------------------------------------------------------------------------
|
| PURPOSE:
| Advanced animated security visualization component.
|
| FEATURES:
|
| ✔ Circular Security Score Meter
| ✔ Animated Progress Rendering
| ✔ Threat Level Visualization
| ✔ AI Security Pulse
| ✔ Neon Glow Rendering
| ✔ Gradient Ring Effects
| ✔ Rotating Scanner Effect
| ✔ AMOLED Optimized
| ✔ Cyberpunk Compatible
| ✔ Glassmorphism Ready
| ✔ Dashboard Analytics Ready
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| SecurityScoreRing(
|     securityScore = 92,
|     title = "System Protection"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SECURITY STATUS SYSTEM
   ========================================================= */

enum class SecurityStatus {

    SECURE,

    PROTECTED,

    WARNING,

    DANGER,

    CRITICAL
}



/* =========================================================
   SECURITY STYLE DATA
   ========================================================= */

data class SecurityRingStyle(

    val label: String,

    val color: Color,

    val gradient: Brush,

    val icon: ImageVector
)



/* =========================================================
   SECURITY STYLE ENGINE
   ========================================================= */

object SecurityRingEngine {

    fun style(
        score: Int
    ): SecurityRingStyle {

        return when {

            score >= 90 -> SecurityRingStyle(

                label = "Secure",

                color = Threat_Low,

                gradient = ThreatGradients.LowThreat,

                icon = Icons.Default.VerifiedUser
            )

            score >= 70 -> SecurityRingStyle(

                label = "Protected",

                color = AI_Active,

                gradient = AIGradients.Scanner,

                icon = Icons.Default.Security
            )

            score >= 50 -> SecurityRingStyle(

                label = "Warning",

                color = Threat_Medium,

                gradient = ThreatGradients.MediumThreat,

                icon = Icons.Default.Warning
            )

            else -> SecurityRingStyle(

                label = "Critical",

                color = Threat_Critical,

                gradient = ThreatGradients.CriticalThreat,

                icon = Icons.Default.Warning
            )
        }
    }
}



/* =========================================================
   MAIN SECURITY SCORE RING
   ========================================================= */

@Composable
fun SecurityScoreRing(

    modifier: Modifier = Modifier,

    securityScore: Int,

    title: String = "Security Status",

    size: Int = 240,

    strokeWidth: Float = 22f,

    animated: Boolean = true,

    showScannerEffect: Boolean = true,

    enableGlow: Boolean = true
) {

    val style =
        SecurityRingEngine.style(
            securityScore
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED SCORE
    |--------------------------------------------------------------------------
    */

    val animatedProgress by animateFloatAsState(

        targetValue = securityScore / 100f,

        animationSpec = tween(

            durationMillis = 1800,

            easing = FastOutSlowInEasing
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ROTATING SCANNER
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val rotationAngle by infiniteTransition.animateFloat(

        initialValue = 0f,

        targetValue = 360f,

        animationSpec = infiniteRepeatable(

            animation = tween(

                durationMillis = 6000,

                easing = LinearEasing
            )
        )
    )



    /*
    |--------------------------------------------------------------------------
    | PULSE GLOW
    |--------------------------------------------------------------------------
    */

    val glowAlpha by infiniteTransition.animateFloat(

        initialValue = 0.4f,

        targetValue = 1f,

        animationSpec = infiniteRepeatable(

            animation = tween(1200),

            repeatMode = RepeatMode.Reverse
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
                    if (enableGlow)
                        SentriXShadow.Huge
                    else
                        SentriXShadow.Small,

                shape = CircleShape,

                ambientColor =
                    style.color.copy(
                        alpha = glowAlpha
                    ),

                spotColor =
                    style.color.copy(
                        alpha = glowAlpha
                    )
            )
            .clip(CircleShape)
            .background(
                color = Background_Card
            )
            .border(

                width = 1.2.dp,

                color =
                    style.color.copy(
                        alpha = 0.4f
                    ),

                shape = CircleShape
            ),

        contentAlignment =
            Alignment.Center
    ) {

        /*
        |--------------------------------------------------------------------------
        | CYBER GRID BACKGROUND
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .matchParentSize()
                .alpha(0.08f)
        ) {

            val gridSpacing = 24.dp.toPx()

            for (
                x in 0..size step 24
            ) {

                drawLine(

                    color = style.color,

                    start = Offset(
                        x.toFloat(),
                        0f
                    ),

                    end = Offset(
                        x.toFloat(),
                        size.toFloat()
                    ),

                    strokeWidth = 1f
                )
            }

            for (
                y in 0..size step 24
            ) {

                drawLine(

                    color = style.color,

                    start = Offset(
                        0f,
                        y.toFloat()
                    ),

                    end = Offset(
                        size.toFloat(),
                        y.toFloat()
                    ),

                    strokeWidth = 1f
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | MAIN RING CANVAS
        |--------------------------------------------------------------------------
        */

        Canvas(

            modifier = Modifier
                .fillMaxSize()
                .padding(18.dp)
        ) {

            val canvasSize =
                size.minDimension

            val sweepAngle =
                360 * animatedProgress

            val topLeft =
                Offset(
                    strokeWidth / 2,
                    strokeWidth / 2
                )

            val arcSize =
                Size(
                    canvasSize - strokeWidth,
                    canvasSize - strokeWidth
                )



            /*
            |--------------------------------------------------------------------------
            | BACKGROUND RING
            |--------------------------------------------------------------------------
            */

            drawArc(

                color =
                    Color.White.copy(
                        alpha = 0.08f
                    ),

                startAngle = -90f,

                sweepAngle = 360f,

                useCenter = false,

                topLeft = topLeft,

                size = arcSize,

                style = Stroke(
                    width = strokeWidth
                )
            )



            /*
            |--------------------------------------------------------------------------
            | MAIN PROGRESS RING
            |--------------------------------------------------------------------------
            */

            drawArc(

                brush = style.gradient,

                startAngle = -90f,

                sweepAngle = sweepAngle,

                useCenter = false,

                topLeft = topLeft,

                size = arcSize,

                style = Stroke(

                    width = strokeWidth,

                    cap = StrokeCap.Round
                )
            )



            /*
            |--------------------------------------------------------------------------
            | SCANNER EFFECT
            |--------------------------------------------------------------------------
            */

            if (showScannerEffect) {

                rotate(rotationAngle) {

                    drawLine(

                        brush = Brush.linearGradient(

                            colors = listOf(

                                style.color.copy(
                                    alpha = 0f
                                ),

                                style.color.copy(
                                    alpha = 0.8f
                                )
                            )
                        ),

                        start = center,

                        end = Offset(
                            center.x,
                            0f
                        ),

                        strokeWidth = 4f
                    )
                }
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
            | ICON
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(68.dp)
                    .clip(CircleShape)
                    .background(

                        color =
                            style.color.copy(
                                alpha = 0.12f
                            )
                    )
                    .border(

                        width = 1.dp,

                        color = style.color,

                        shape = CircleShape
                    ),

                contentAlignment =
                    Alignment.Center
            ) {

                Icon(

                    imageVector = style.icon,

                    contentDescription = null,

                    tint = style.color,

                    modifier = Modifier.size(
                        IconDimensions.ExtraLarge
                    )
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Large
                )
            )



            /*
            |--------------------------------------------------------------------------
            | SECURITY SCORE
            |--------------------------------------------------------------------------
            */

            Text(

                text = "$securityScore%",

                style =
                    DashboardTypography.Metric,

                color = Text_Primary,

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
            | SECURITY LABEL
            |--------------------------------------------------------------------------
            */

            Text(

                text = style.label,

                style =
                    SecurityTypography.ThreatWarning,

                color = style.color
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraSmall
                )
            )



            /*
            |--------------------------------------------------------------------------
            | TITLE
            |--------------------------------------------------------------------------
            */

            Text(

                text = title,

                style =
                    BodyTypography.Small,

                color = Text_Secondary
            )
        }
    }
}



/* =========================================================
   MINI SECURITY SCORE RING
   ========================================================= */

@Composable
fun MiniSecurityScoreRing(

    securityScore: Int
) {

    SecurityScoreRing(

        securityScore = securityScore,

        size = 140,

        strokeWidth = 14f,

        showScannerEffect = false
    )
}



/* =========================================================
   AI SECURITY RING
   ========================================================= */

@Composable
fun AISecurityRing(

    aiConfidence: Int
) {

    SecurityScoreRing(

        securityScore = aiConfidence,

        title = "AI Protection",

        showScannerEffect = true
    )
}



/* =========================================================
   FUTURE SECURITY RING EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time holographic rendering
| ✔ GPU accelerated neon arcs
| ✔ Interactive threat visualization
| ✔ AI adaptive ring animation
| ✔ 3D radar rendering
| ✔ Dynamic attack heatmaps
| ✔ Runtime cyber-grid engine
| ✔ Threat prediction overlays
| ✔ VR/AR visualization support
| ✔ Quantum security analytics
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX SECURITY SCORE RING
|--------------------------------------------------------------------------
*/
