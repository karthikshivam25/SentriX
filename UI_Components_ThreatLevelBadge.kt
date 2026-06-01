package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX THREAT LEVEL BADGE
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise threat severity badge system for SentriX.
|
| FEATURES:
|
| ✔ Threat Severity Visualization
| ✔ Animated Live Pulse
| ✔ AI Threat Indicators
| ✔ Gradient Rendering
| ✔ Neon Glow Effects
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Glassmorphism Compatible
| ✔ Enterprise Security Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| ThreatLevelBadge(
|     threatLevel = ThreatBadgeLevel.CRITICAL
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   THREAT BADGE LEVELS
   ========================================================= */

enum class ThreatBadgeLevel {

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL,

    SEVERE
}



/* =========================================================
   BADGE STYLE MODEL
   ========================================================= */

data class ThreatBadgeStyle(

    val label: String,

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector
)



/* =========================================================
   THREAT BADGE ENGINE
   ========================================================= */

object ThreatBadgeEngine {

    fun style(
        level: ThreatBadgeLevel
    ): ThreatBadgeStyle {

        return when (level) {

            ThreatBadgeLevel.SAFE ->

                ThreatBadgeStyle(

                    label = "SAFE",

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser
                )

            ThreatBadgeLevel.LOW ->

                ThreatBadgeStyle(

                    label = "LOW",

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.Security
                )

            ThreatBadgeLevel.MEDIUM ->

                ThreatBadgeStyle(

                    label = "MEDIUM",

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber
                )

            ThreatBadgeLevel.HIGH ->

                ThreatBadgeStyle(

                    label = "HIGH",

                    gradient =
                        ThreatGradients.HighThreat,

                    glowColor =
                        Threat_High,

                    borderColor =
                        Threat_High,

                    icon =
                        Icons.Default.ReportProblem
                )

            ThreatBadgeLevel.CRITICAL ->

                ThreatBadgeStyle(

                    label = "CRITICAL",

                    gradient =
                        ThreatGradients
                            .CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            ThreatBadgeLevel.SEVERE ->

                ThreatBadgeStyle(

                    label = "SEVERE",

                    gradient =
                        ThreatGradients
                            .SevereThreat,

                    glowColor =
                        Threat_Severe,

                    borderColor =
                        Threat_Severe,

                    icon =
                        Icons.Default.Dangerous
                )
        }
    }
}



/* =========================================================
   MAIN THREAT LEVEL BADGE
   ========================================================= */

@Composable
fun ThreatLevelBadge(

    modifier: Modifier = Modifier,

    threatLevel: ThreatBadgeLevel =
        ThreatBadgeLevel.LOW,

    showPulseEffect: Boolean = true,

    enableGlow: Boolean = true,

    showIcon: Boolean = true
) {

    val style =
        ThreatBadgeEngine.style(
            threatLevel
        )



    /*
    |--------------------------------------------------------------------------
    | LIVE PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.35f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(900),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | GLOW ANIMATION
    |--------------------------------------------------------------------------
    */

    val glowScale by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = 1.04f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | BORDER COLOR ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue =
            style.borderColor,

        animationSpec =
            tween(500)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN BADGE CONTAINER
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .graphicsLayer {

                if (
                    enableGlow
                ) {

                    scaleX = glowScale

                    scaleY = glowScale
                }
            }
            .shadow(

                elevation = if (
                    enableGlow
                )

                    SentriXShadow.Medium

                else

                    0.dp,

                shape =
                    RoundedCornerShape(
                        100.dp
                    ),

                ambientColor =
                    style.glowColor.copy(

                        alpha = if (
                            showPulseEffect
                        )

                            pulseAlpha

                        else

                            0.18f
                    ),

                spotColor =
                    style.glowColor.copy(

                        alpha = if (
                            showPulseEffect
                        )

                            pulseAlpha

                        else

                            0.18f
                    )
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
            .border(

                width = 1.2.dp,

                color =
                    animatedBorderColor,

                shape =
                    RoundedCornerShape(
                        100.dp
                    )
            )
            .padding(

                horizontal =
                    SentriXSpacing.Large,

                vertical =
                    SentriXSpacing.Small
            ),

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | LIVE INDICATOR DOT
        |--------------------------------------------------------------------------
        */

        if (showPulseEffect) {

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
                        Color.White
                    )
            )

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | THREAT ICON
        |--------------------------------------------------------------------------
        */

        if (showIcon) {

            Icon(

                imageVector =
                    style.icon,

                contentDescription = null,

                tint =
                    Text_Primary,

                modifier = Modifier.size(
                    IconDimensions.Medium
                )
            )

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | THREAT LABEL
        |--------------------------------------------------------------------------
        */

        Text(

            text =
                style.label,

            style =
                ButtonTypography.Medium,

            color =
                Text_Primary,

            fontWeight =
                FontWeight.ExtraBold
        )
    }
}



/* =========================================================
   MINI THREAT BADGE
   ========================================================= */

@Composable
fun MiniThreatLevelBadge(

    threatLevel: ThreatBadgeLevel
) {

    ThreatLevelBadge(

        threatLevel = threatLevel,

        enableGlow = false,

        showPulseEffect = false
    )
}



/* =========================================================
   LIVE THREAT BADGE
   ========================================================= */

@Composable
fun LiveThreatBadge(

    threatLevel: ThreatBadgeLevel
) {

    ThreatLevelBadge(

        threatLevel = threatLevel,

        showPulseEffect = true,

        enableGlow = true
    )
}



/* =========================================================
   CYBERPUNK THREAT BADGE
   ========================================================= */

@Composable
fun CyberThreatBadge(

    threatLevel: ThreatBadgeLevel
) {

    ThreatLevelBadge(

        threatLevel = threatLevel,

        showPulseEffect = true,

        enableGlow = true,

        showIcon = true
    )
}



/* =========================================================
   FUTURE THREAT BADGE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time attack indicators
| ✔ AI adaptive severity rendering
| ✔ GPU neon badge rendering
| ✔ Dynamic holographic effects
| ✔ Runtime pulse synchronization
| ✔ Quantum security indicators
| ✔ VR/AR badge rendering
| ✔ Threat clustering visuals
| ✔ Interactive cyber-grid overlays
| ✔ Live attack stream integration
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX THREAT LEVEL BADGE
|--------------------------------------------------------------------------
*/
