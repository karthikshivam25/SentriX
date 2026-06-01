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
| SENTRIX STATUS CHIP
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise reusable status chip component system.
|
| FEATURES:
|
| ✔ Live Status Indicators
| ✔ Animated Pulse Effects
| ✔ AI Monitoring Status
| ✔ Threat Visualization
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Gradient Rendering
| ✔ Lightweight Dashboard UI
| ✔ Dynamic Glow Effects
| ✔ Enterprise Ready Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| StatusChip(
|     text = "Protected",
|     statusType = StatusChipType.SUCCESS
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   STATUS CHIP TYPES
   ========================================================= */

enum class StatusChipType {

    SUCCESS,

    WARNING,

    DANGER,

    INFO,

    AI,

    CYBER,

    OFFLINE,

    LIVE
}



/* =========================================================
   STATUS CHIP STYLE MODEL
   ========================================================= */

data class StatusChipStyle(

    val backgroundBrush: Brush,

    val borderColor: Color,

    val textColor: Color,

    val glowColor: Color,

    val icon: ImageVector
)



/* =========================================================
   STATUS CHIP ENGINE
   ========================================================= */

object StatusChipEngine {

    fun style(
        type: StatusChipType
    ): StatusChipStyle {

        return when (type) {

            StatusChipType.SUCCESS ->

                StatusChipStyle(

                    backgroundBrush =
                        ThreatGradients.LowThreat,

                    borderColor =
                        Threat_Low,

                    textColor =
                        Text_Primary,

                    glowColor =
                        Threat_Low,

                    icon =
                        Icons.Default.Verified
                )

            StatusChipType.WARNING ->

                StatusChipStyle(

                    backgroundBrush =
                        ThreatGradients.MediumThreat,

                    borderColor =
                        Threat_Medium,

                    textColor =
                        Text_Dark,

                    glowColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.Warning
                )

            StatusChipType.DANGER ->

                StatusChipStyle(

                    backgroundBrush =
                        ThreatGradients
                            .CriticalThreat,

                    borderColor =
                        Threat_Critical,

                    textColor =
                        Text_Primary,

                    glowColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            StatusChipType.INFO ->

                StatusChipStyle(

                    backgroundBrush =
                        BrandGradients.Primary,

                    borderColor =
                        SentriX_AccentCyan,

                    textColor =
                        Text_Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    icon =
                        Icons.Default.Info
                )

            StatusChipType.AI ->

                StatusChipStyle(

                    backgroundBrush =
                        AIGradients.Neural,

                    borderColor =
                        AI_Active,

                    textColor =
                        Text_Primary,

                    glowColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory
                )

            StatusChipType.CYBER ->

                StatusChipStyle(

                    backgroundBrush =
                        CyberpunkGradients
                            .NeonPurple,

                    borderColor =
                        Color(0xFFFF00FF),

                    textColor =
                        Text_Primary,

                    glowColor =
                        Color(0xFFFF00FF),

                    icon =
                        Icons.Default.Bolt
                )

            StatusChipType.OFFLINE ->

                StatusChipStyle(

                    backgroundBrush =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF3A3A3A),

                                Color(0xFF555555)
                            )
                        ),

                    borderColor =
                        Color(0xFF888888),

                    textColor =
                        Text_Primary,

                    glowColor =
                        Color(0xFF888888),

                    icon =
                        Icons.Default.CloudOff
                )

            StatusChipType.LIVE ->

                StatusChipStyle(

                    backgroundBrush =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFFFF1744),

                                Color(0xFFFF5252)
                            )
                        ),

                    borderColor =
                        Color(0xFFFF1744),

                    textColor =
                        Text_Primary,

                    glowColor =
                        Color(0xFFFF1744),

                    icon =
                        Icons.Default.FiberManualRecord
                )
        }
    }
}



/* =========================================================
   MAIN STATUS CHIP
   ========================================================= */

@Composable
fun StatusChip(

    modifier: Modifier = Modifier,

    text: String,

    statusType: StatusChipType =
        StatusChipType.INFO,

    enableGlow: Boolean = true,

    enablePulse: Boolean = true,

    showIcon: Boolean = true
) {

    val style =
        StatusChipEngine.style(
            statusType
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

                    animation = tween(1000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED BORDER COLOR
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
    | MAIN CHIP CONTAINER
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .shadow(

                elevation = if (
                    enableGlow
                )

                    SentriXShadow.Small

                else

                    0.dp,

                shape =
                    RoundedCornerShape(
                        100.dp
                    ),

                ambientColor =
                    style.glowColor.copy(

                        alpha = if (
                            enablePulse
                        )

                            pulseAlpha

                        else

                            0.18f
                    ),

                spotColor =
                    style.glowColor.copy(

                        alpha = if (
                            enablePulse
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
                    style.backgroundBrush
            )
            .border(

                width = 1.dp,

                color =
                    animatedBorderColor,

                shape =
                    RoundedCornerShape(
                        100.dp
                    )
            )
            .padding(

                horizontal =
                    SentriXSpacing.Medium,

                vertical =
                    SentriXSpacing.Small
            ),

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | STATUS ICON
        |--------------------------------------------------------------------------
        */

        if (showIcon) {

            Box(

                modifier = Modifier
                    .size(20.dp)
                    .alpha(
                        if (
                            enablePulse
                        )

                            pulseAlpha

                        else

                            1f
                    )
                    .clip(
                        CircleShape
                    )
                    .background(

                        color =
                            Color.White.copy(
                                alpha = 0.12f
                            )
                    ),

                contentAlignment =
                    Alignment.Center
            ) {

                Icon(

                    imageVector =
                        style.icon,

                    contentDescription = null,

                    tint =
                        style.textColor,

                    modifier = Modifier.size(
                        IconDimensions
                            .Small
                    )
                )
            }

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | STATUS TEXT
        |--------------------------------------------------------------------------
        */

        Text(

            text = text,

            style =
                BodyTypography.Small,

            color =
                style.textColor,

            fontWeight =
                FontWeight.Bold
        )
    }
}



/* =========================================================
   LIVE STATUS CHIP
   ========================================================= */

@Composable
fun LiveStatusChip(

    text: String = "LIVE"
) {

    StatusChip(

        text = text,

        statusType =
            StatusChipType.LIVE
    )
}



/* =========================================================
   AI STATUS CHIP
   ========================================================= */

@Composable
fun AIStatusChip(

    text: String = "AI ACTIVE"
) {

    StatusChip(

        text = text,

        statusType =
            StatusChipType.AI
    )
}



/* =========================================================
   CYBER STATUS CHIP
   ========================================================= */

@Composable
fun CyberStatusChip(

    text: String = "CYBER MODE"
) {

    StatusChip(

        text = text,

        statusType =
            StatusChipType.CYBER
    )
}



/* =========================================================
   MINI STATUS CHIP
   ========================================================= */

@Composable
fun MiniStatusChip(

    text: String,

    statusType: StatusChipType
) {

    StatusChip(

        text = text,

        statusType = statusType,

        enableGlow = false,

        enablePulse = false
    )
}



/* =========================================================
   FUTURE STATUS CHIP EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time status streaming
| ✔ AI adaptive chip rendering
| ✔ GPU neon rendering
| ✔ Dynamic holographic chips
| ✔ Runtime color engine
| ✔ Interactive status overlays
| ✔ Voice reactive indicators
| ✔ Threat pulse synchronization
| ✔ Cyber-grid micro animations
| ✔ VR/AR chip rendering
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX STATUS CHIP
|--------------------------------------------------------------------------
*/
