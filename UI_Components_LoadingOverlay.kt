package com.sentrix.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX LOADING OVERLAY
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise futuristic loading overlay system for SentriX.
|
| FEATURES:
|
| ✔ Full-Screen Loading Overlay
| ✔ AI Neural Loading Animation
| ✔ Cyber Radar Scanner
| ✔ Dynamic Glow Rendering
| ✔ Glassmorphism Blur Layer
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Enterprise UX Architecture
| ✔ Threat Analysis Visualization
| ✔ Cyberpunk Compatible
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| LoadingOverlay(
|     visible = isLoading,
|     message = "Analyzing Threats..."
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   LOADING TYPES
   ========================================================= */

enum class LoadingOverlayType {

    DEFAULT,

    AI_ANALYZING,

    SECURITY_SCAN,

    NETWORK_MONITORING,

    THREAT_DETECTION,

    CYBERPUNK
}



/* =========================================================
   LOADING STYLE MODEL
   ========================================================= */

data class LoadingOverlayStyle(

    val primaryColor: Color,

    val secondaryColor: Color,

    val gradient: Brush,

    val icon: androidx.compose.ui.graphics.vector.ImageVector
)



/* =========================================================
   LOADING STYLE ENGINE
   ========================================================= */

object LoadingOverlayEngine {

    fun style(
        type: LoadingOverlayType
    ): LoadingOverlayStyle {

        return when (type) {

            LoadingOverlayType.DEFAULT ->

                LoadingOverlayStyle(

                    primaryColor =
                        SentriX_AccentCyan,

                    secondaryColor =
                        SentriX_AccentBlue,

                    gradient =
                        BrandGradients.Primary,

                    icon =
                        Icons.Default.Security
                )

            LoadingOverlayType.AI_ANALYZING ->

                LoadingOverlayStyle(

                    primaryColor =
                        AI_Active,

                    secondaryColor =
                        SentriX_AccentPurple,

                    gradient =
                        AIGradients.Neural,

                    icon =
                        Icons.Default.Memory
                )

            LoadingOverlayType.SECURITY_SCAN ->

                LoadingOverlayStyle(

                    primaryColor =
                        Threat_Low,

                    secondaryColor =
                        SentriX_AccentGreen,

                    gradient =
                        ThreatGradients.LowThreat,

                    icon =
                        Icons.Default.Security
                )

            LoadingOverlayType.NETWORK_MONITORING ->

                LoadingOverlayStyle(

                    primaryColor =
                        Network_Incoming,

                    secondaryColor =
                        SentriX_AccentBlue,

                    gradient =
                        AnalyticsGradients
                            .NetworkTraffic,

                    icon =
                        Icons.Default.Memory
                )

            LoadingOverlayType.THREAT_DETECTION ->

                LoadingOverlayStyle(

                    primaryColor =
                        Threat_Critical,

                    secondaryColor =
                        Threat_High,

                    gradient =
                        ThreatGradients
                            .CriticalThreat,

                    icon =
                        Icons.Default.Security
                )

            LoadingOverlayType.CYBERPUNK ->

                LoadingOverlayStyle(

                    primaryColor =
                        Color(0xFFFF00FF),

                    secondaryColor =
                        Color(0xFF00FFFF),

                    gradient =
                        CyberpunkGradients
                            .Hologram,

                    icon =
                        Icons.Default.Memory
                )
        }
    }
}



/* =========================================================
   MAIN LOADING OVERLAY
   ========================================================= */

@Composable
fun LoadingOverlay(

    visible: Boolean,

    modifier: Modifier = Modifier,

    message: String =
        "Loading...",

    subMessage: String =
        "Initializing SentriX security engine",

    loadingType: LoadingOverlayType =
        LoadingOverlayType.DEFAULT,

    enableBackgroundBlur: Boolean = true,

    showScannerEffect: Boolean = true
) {

    val style =
        LoadingOverlayEngine.style(
            loadingType
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
    | ROTATION ANIMATION
    |--------------------------------------------------------------------------
    */

    val rotationAngle by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 360f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 3500,

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

                    animation = tween(1000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | FLOATING EFFECT
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -6f,

            targetValue = 6f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | VISIBILITY LAYER
    |--------------------------------------------------------------------------
    */

    AnimatedVisibility(

        visible = visible,

        enter = fadeIn(),

        exit = fadeOut()
    ) {

        Box(

            modifier = modifier
                .fillMaxSize()
                .background(

                    color =
                        Background_Main.copy(
                            alpha = 0.92f
                        )
                )
                .then(

                    if (
                        enableBackgroundBlur
                    )

                        Modifier.blur(4.dp)

                    else

                        Modifier
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
                    .fillMaxSize()
                    .alpha(0.06f)
            ) {

                val spacing = 60f

                for (
                    x in 0..size.width.toInt()
                            step spacing.toInt()
                ) {

                    drawLine(

                        color =
                            style.primaryColor,

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
                            Offset(
                                0f,
                                y.toFloat()
                            ),

                        end =
                            Offset(
                                size.width,
                                y.toFloat()
                            ),

                        strokeWidth = 1f
                    )
                }
            }



            /*
            |--------------------------------------------------------------------------
            | MAIN LOADING PANEL
            |--------------------------------------------------------------------------
            */

            Column(

                horizontalAlignment =
                    Alignment.CenterHorizontally
            ) {

                /*
                |--------------------------------------------------------------------------
                | LOADING CORE
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .size(220.dp),

                    contentAlignment =
                        Alignment.Center
                ) {

                    /*
                    |--------------------------------------------------------------------------
                    | OUTER SCANNER RING
                    |--------------------------------------------------------------------------
                    */

                    if (showScannerEffect) {

                        Canvas(

                            modifier = Modifier
                                .fillMaxSize()
                                .rotate(
                                    rotationAngle
                                )
                        ) {

                            drawArc(

                                brush =
                                    Brush.sweepGradient(

                                        colors = listOf(

                                            Color.Transparent,

                                            style.primaryColor,

                                            Color.Transparent
                                        )
                                    ),

                                startAngle = 0f,

                                sweepAngle = 120f,

                                useCenter = false,

                                style = Stroke(
                                    width = 12f
                                )
                            )
                        }
                    }



                    /*
                    |--------------------------------------------------------------------------
                    | GLOW LAYER
                    |--------------------------------------------------------------------------
                    */

                    Box(

                        modifier = Modifier
                            .size(160.dp)
                            .alpha(
                                pulseAlpha * 0.28f
                            )
                            .blur(20.dp)
                            .clip(
                                CircleShape
                            )
                            .background(
                                style.primaryColor
                            )
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | MAIN CORE
                    |--------------------------------------------------------------------------
                    */

                    Box(

                        modifier = Modifier
                            .offset(
                                y = floatingOffset.dp
                            )
                            .size(130.dp)
                            .shadow(

                                elevation =
                                    SentriXShadow.Huge,

                                shape =
                                    CircleShape,

                                ambientColor =
                                    style.primaryColor
                                        .copy(
                                            alpha = pulseAlpha
                                        ),

                                spotColor =
                                    style.primaryColor
                                        .copy(
                                            alpha = pulseAlpha
                                        )
                            )
                            .clip(
                                CircleShape
                            )
                            .background(

                                brush =
                                    style.gradient
                            )
                            .border(

                                width = 1.5.dp,

                                color =
                                    Color.White.copy(
                                        alpha = 0.22f
                                    ),

                                shape =
                                    CircleShape
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
                                .size(92.dp)
                                .alpha(0.14f)
                                .clip(
                                    CircleShape
                                )
                                .background(
                                    Color.White
                                )
                        )



                        /*
                        |--------------------------------------------------------------------------
                        | MAIN ICON
                        |--------------------------------------------------------------------------
                        */

                        Icon(

                            imageVector =
                                style.icon,

                            contentDescription =
                                null,

                            tint =
                                Text_Primary,

                            modifier = Modifier.size(
                                IconDimensions.Huge
                            )
                        )
                    }
                }



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.ExtraLarge
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | LIVE INDICATOR
                |--------------------------------------------------------------------------
                */

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
                                style.primaryColor
                            )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )

                    Text(

                        text = "SYSTEM PROCESSING",

                        style =
                            TerminalTypography.Body,

                        color =
                            style.primaryColor
                    )
                }



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Large
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | MAIN MESSAGE
                |--------------------------------------------------------------------------
                */

                Text(

                    text = message,

                    style =
                        HeadlineTypography.Medium,

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
                | SUB MESSAGE
                |--------------------------------------------------------------------------
                */

                Text(

                    text = subMessage,

                    style =
                        BodyTypography.Medium,

                    color =
                        Text_Secondary
                )



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.ExtraLarge
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | LOADING BAR
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .width(260.dp)
                        .height(8.dp)
                        .clip(
                            RoundedCornerShape(
                                100.dp
                            )
                        )
                        .background(

                            color =
                                Color.White.copy(
                                    alpha = 0.08f
                                )
                        )
                ) {

                    Box(

                        modifier = Modifier
                            .fillMaxHeight()
                            .fillMaxWidth(
                                pulseAlpha
                            )
                            .clip(
                                RoundedCornerShape(
                                    100.dp
                                )
                            )
                            .background(

                                brush =
                                    style.gradient
                            )
                    )
                }
            }
        }
    }
}



/* =========================================================
   AI LOADING OVERLAY
   ========================================================= */

@Composable
fun AILoadingOverlay(

    visible: Boolean
) {

    LoadingOverlay(

        visible = visible,

        message =
            "AI Threat Analysis",

        subMessage =
            "SentriX neural engine is analyzing system behavior",

        loadingType =
            LoadingOverlayType.AI_ANALYZING
    )
}



/* =========================================================
   SECURITY SCAN OVERLAY
   ========================================================= */

@Composable
fun SecurityScanOverlay(

    visible: Boolean
) {

    LoadingOverlay(

        visible = visible,

        message =
            "Security Scan Running",

        subMessage =
            "Scanning for malicious processes and vulnerabilities",

        loadingType =
            LoadingOverlayType.SECURITY_SCAN
    )
}



/* =========================================================
   THREAT DETECTION OVERLAY
   ========================================================= */

@Composable
fun ThreatDetectionOverlay(

    visible: Boolean
) {

    LoadingOverlay(

        visible = visible,

        message =
            "Threat Detected",

        subMessage =
            "Analyzing suspicious activity and isolating threats",

        loadingType =
            LoadingOverlayType.THREAT_DETECTION
    )
}



/* =========================================================
   FUTURE LOADING ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ GPU holographic rendering
| ✔ AI adaptive loading engine
| ✔ Dynamic cyber-grid overlays
| ✔ Quantum system initialization
| ✔ VR/AR loading visualization
| ✔ Voice-assisted loading status
| ✔ Runtime analytics rendering
| ✔ Interactive system diagnostics
| ✔ Real-time threat visualization
| ✔ Neural loading intelligence
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX LOADING OVERLAY
|--------------------------------------------------------------------------
*/
