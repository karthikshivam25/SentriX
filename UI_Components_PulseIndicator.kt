package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX PULSE INDICATOR
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic real-time pulse indicator system for SentriX.
|
| FEATURES:
|
| ✔ Live Pulse Animation
| ✔ AI Activity Visualization
| ✔ Threat Monitoring Status
| ✔ Multi-Layer Glow Rendering
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Real-Time System Monitoring
| ✔ Gradient Pulse Effects
| ✔ Enterprise Security UI
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| PulseIndicator(
|     pulseType = PulseIndicatorType.ACTIVE,
|     label = "Live Protection"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   PULSE TYPES
   ========================================================= */

enum class PulseIndicatorType {

    ACTIVE,

    SUCCESS,

    WARNING,

    DANGER,

    AI,

    NETWORK,

    OFFLINE,

    CYBERPUNK
}



/* =========================================================
   PULSE STYLE MODEL
   ========================================================= */

data class PulseIndicatorStyle(

    val pulseColor: Color,

    val glowColor: Color,

    val gradient: Brush,

    val icon: ImageVector
)



/* =========================================================
   PULSE STYLE ENGINE
   ========================================================= */

object PulseIndicatorEngine {

    fun style(
        type: PulseIndicatorType
    ): PulseIndicatorStyle {

        return when (type) {

            PulseIndicatorType.ACTIVE ->

                PulseIndicatorStyle(

                    pulseColor =
                        SentriX_AccentCyan,

                    glowColor =
                        SentriX_AccentBlue,

                    gradient =
                        BrandGradients.Primary,

                    icon =
                        Icons.Default.FiberManualRecord
                )

            PulseIndicatorType.SUCCESS ->

                PulseIndicatorStyle(

                    pulseColor =
                        Threat_Low,

                    glowColor =
                        Threat_Low,

                    gradient =
                        ThreatGradients.LowThreat,

                    icon =
                        Icons.Default.VerifiedUser
                )

            PulseIndicatorType.WARNING ->

                PulseIndicatorStyle(

                    pulseColor =
                        Threat_Medium,

                    glowColor =
                        Threat_Medium,

                    gradient =
                        ThreatGradients.MediumThreat,

                    icon =
                        Icons.Default.WarningAmber
                )

            PulseIndicatorType.DANGER ->

                PulseIndicatorStyle(

                    pulseColor =
                        Threat_Critical,

                    glowColor =
                        Threat_Critical,

                    gradient =
                        ThreatGradients.CriticalThreat,

                    icon =
                        Icons.Default.GppBad
                )

            PulseIndicatorType.AI ->

                PulseIndicatorStyle(

                    pulseColor =
                        AI_Active,

                    glowColor =
                        AI_Active,

                    gradient =
                        AIGradients.Neural,

                    icon =
                        Icons.Default.Memory
                )

            PulseIndicatorType.NETWORK ->

                PulseIndicatorStyle(

                    pulseColor =
                        Network_Incoming,

                    glowColor =
                        Network_Incoming,

                    gradient =
                        AnalyticsGradients.NetworkTraffic,

                    icon =
                        Icons.Default.Wifi
                )

            PulseIndicatorType.OFFLINE ->

                PulseIndicatorStyle(

                    pulseColor =
                        Text_Muted,

                    glowColor =
                        Text_Muted,

                    gradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF444444),

                                Color(0xFF666666)
                            )
                        ),

                    icon =
                        Icons.Default.CloudOff
                )

            PulseIndicatorType.CYBERPUNK ->

                PulseIndicatorStyle(

                    pulseColor =
                        Color(0xFFFF00FF),

                    glowColor =
                        Color(0xFFFF00FF),

                    gradient =
                        CyberpunkGradients.Hologram,

                    icon =
                        Icons.Default.Bolt
                )
        }
    }
}



/* =========================================================
   MAIN PULSE INDICATOR
   ========================================================= */

@Composable
fun PulseIndicator(

    modifier: Modifier = Modifier,

    pulseType: PulseIndicatorType =
        PulseIndicatorType.ACTIVE,

    label: String = "",

    showLabel: Boolean = true,

    showIcon: Boolean = true,

    indicatorSize: Int = 18,

    enableGlow: Boolean = true,

    enableRipple: Boolean = true
) {

    val style =
        PulseIndicatorEngine.style(
            pulseType
        )



    /*
    |--------------------------------------------------------------------------
    | INFINITE ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | MAIN PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.25f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 900
                    ),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | RIPPLE SCALE ANIMATION
    |--------------------------------------------------------------------------
    */

    val rippleScale by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = 2.4f,

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
    | FLOATING ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -1f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1500),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED COLOR
    |--------------------------------------------------------------------------
    */

    val animatedPulseColor by animateColorAsState(

        targetValue =
            style.pulseColor,

        animationSpec =
            tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier,

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | PULSE VISUALIZER
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(
                    (indicatorSize * 3).dp
                ),

            contentAlignment =
                Alignment.Center
        ) {

            /*
            |--------------------------------------------------------------------------
            | RIPPLE EFFECT
            |--------------------------------------------------------------------------
            */

            if (enableRipple) {

                Box(

                    modifier = Modifier
                        .graphicsLayer {

                            scaleX = rippleScale

                            scaleY = rippleScale
                        }
                        .size(
                            indicatorSize.dp
                        )
                        .alpha(

                            1f - (
                                rippleScale / 2.5f
                            )
                        )
                        .clip(
                            CircleShape
                        )
                        .background(

                            color =
                                animatedPulseColor
                                    .copy(
                                        alpha = 0.18f
                                    )
                        )
                )
            }



            /*
            |--------------------------------------------------------------------------
            | OUTER GLOW CIRCLE
            |--------------------------------------------------------------------------
            */

            if (enableGlow) {

                Box(

                    modifier = Modifier
                        .size(
                            (indicatorSize + 12).dp
                        )
                        .alpha(
                            pulseAlpha * 0.35f
                        )
                        .blur(8.dp)
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
            | MAIN INDICATOR
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .offset(
                        y = floatingOffset.dp
                    )
                    .size(
                        indicatorSize.dp
                    )
                    .shadow(

                        elevation =
                            SentriXShadow.Medium,

                        shape =
                            CircleShape,

                        ambientColor =
                            style.glowColor.copy(
                                alpha = pulseAlpha
                            ),

                        spotColor =
                            style.glowColor.copy(
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

                        width = 1.dp,

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
                        .size(
                            (indicatorSize / 2).dp
                        )
                        .alpha(
                            pulseAlpha
                        )
                        .clip(
                            CircleShape
                        )
                        .background(
                            Color.White
                        )
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | LABEL SECTION
        |--------------------------------------------------------------------------
        */

        if (showLabel) {

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )

            Row(

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                /*
                |--------------------------------------------------------------------------
                | ICON
                |--------------------------------------------------------------------------
                */

                if (showIcon) {

                    Icon(

                        imageVector =
                            style.icon,

                        contentDescription =
                            null,

                        tint =
                            animatedPulseColor,

                        modifier = Modifier.size(
                            IconDimensions.Small
                        )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing
                                .ExtraSmall
                        )
                    )
                }



                /*
                |--------------------------------------------------------------------------
                | LABEL TEXT
                |--------------------------------------------------------------------------
                */

                Text(

                    text = label,

                    style =
                        BodyTypography.Small,

                    color =
                        animatedPulseColor,

                    fontWeight =
                        FontWeight.Bold
                )
            }
        }
    }
}



/* =========================================================
   LIVE PULSE INDICATOR
   ========================================================= */

@Composable
fun LivePulseIndicator(

    label: String = "LIVE"
) {

    PulseIndicator(

        pulseType =
            PulseIndicatorType.ACTIVE,

        label = label
    )
}



/* =========================================================
   AI PULSE INDICATOR
   ========================================================= */

@Composable
fun AIPulseIndicator(

    label: String = "AI ACTIVE"
) {

    PulseIndicator(

        pulseType =
            PulseIndicatorType.AI,

        label = label
    )
}



/* =========================================================
   DANGER PULSE INDICATOR
   ========================================================= */

@Composable
fun DangerPulseIndicator(

    label: String = "THREAT DETECTED"
) {

    PulseIndicator(

        pulseType =
            PulseIndicatorType.DANGER,

        label = label
    )
}



/* =========================================================
   MINI PULSE INDICATOR
   ========================================================= */

@Composable
fun MiniPulseIndicator(

    pulseType: PulseIndicatorType
) {

    PulseIndicator(

        pulseType = pulseType,

        showLabel = false,

        showIcon = false,

        indicatorSize = 12,

        enableRipple = false
    )
}



/* =========================================================
   FUTURE PULSE ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive pulse engine
| ✔ GPU neon pulse rendering
| ✔ Real-time attack pulse sync
| ✔ Quantum pulse indicators
| ✔ VR/AR pulse rendering
| ✔ Runtime pulse intelligence
| ✔ Interactive cyber-grid ripples
| ✔ Dynamic threat heartbeat system
| ✔ Voice reactive pulse engine
| ✔ Holographic live indicators
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX PULSE INDICATOR
|--------------------------------------------------------------------------
*/
