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
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX LIVE PROTECTION BANNER
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise live protection status banner for SentriX.
|
| FEATURES:
|
| ✔ Live Protection Monitoring
| ✔ AI Threat Detection Status
| ✔ Real-Time Pulse Effects
| ✔ Dynamic Threat Alerts
| ✔ Gradient Rendering
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Glassmorphism Support
| ✔ Dashboard Ready
| ✔ Enterprise Security Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| LiveProtectionBanner(
|     protectionEnabled = true,
|     protectionScore = 96
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   PROTECTION STATES
   ========================================================= */

enum class ProtectionState {

    FULLY_PROTECTED,

    MONITORING,

    WARNING,

    CRITICAL,

    DISABLED
}



/* =========================================================
   PROTECTION STYLE MODEL
   ========================================================= */

data class ProtectionBannerStyle(

    val title: String,

    val subtitle: String,

    val gradient: Brush,

    val glowColor: Color,

    val icon: androidx.compose.ui.graphics.vector.ImageVector
)



/* =========================================================
   PROTECTION ENGINE
   ========================================================= */

object ProtectionBannerEngine {

    fun style(
        state: ProtectionState
    ): ProtectionBannerStyle {

        return when (state) {

            ProtectionState.FULLY_PROTECTED ->

                ProtectionBannerStyle(

                    title = "System Fully Protected",

                    subtitle =
                        "All SentriX protection layers are active",

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser
                )

            ProtectionState.MONITORING ->

                ProtectionBannerStyle(

                    title = "AI Monitoring Active",

                    subtitle =
                        "Neural security engine is analyzing threats",

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory
                )

            ProtectionState.WARNING ->

                ProtectionBannerStyle(

                    title = "Potential Threat Detected",

                    subtitle =
                        "Suspicious activities require attention",

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber
                )

            ProtectionState.CRITICAL ->

                ProtectionBannerStyle(

                    title = "Critical Security Threat",

                    subtitle =
                        "Immediate action is required",

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            ProtectionState.DISABLED ->

                ProtectionBannerStyle(

                    title = "Protection Disabled",

                    subtitle =
                        "System defenses are currently offline",

                    gradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF3A3A3A),

                                Color(0xFF5A5A5A)
                            )
                        ),

                    glowColor =
                        Color(0xFF888888),

                    icon =
                        Icons.Default.PowerSettingsNew
                )
        }
    }
}



/* =========================================================
   MAIN LIVE PROTECTION BANNER
   ========================================================= */

@Composable
fun LiveProtectionBanner(

    modifier: Modifier = Modifier,

    protectionState: ProtectionState =
        ProtectionState.FULLY_PROTECTED,

    protectionScore: Int = 100,

    showActionButton: Boolean = true,

    actionButtonText: String = "Open Security Center",

    onActionClick: () -> Unit = {}
) {

    val style =
        ProtectionBannerEngine.style(
            protectionState
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

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SCANNER FLOAT ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -3f,

            targetValue = 3f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PROGRESS ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedProgress by animateFloatAsState(

        targetValue =
            protectionScore / 100f,

        animationSpec =
            tween(1400)
    )



    /*
    |--------------------------------------------------------------------------
    | GLOW COLOR ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedGlowColor by animateColorAsState(

        targetValue =
            style.glowColor,

        animationSpec =
            tween(500)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN BANNER CONTAINER
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .fillMaxWidth()
            .shadow(

                elevation =
                    SentriXShadow.Huge,

                shape =
                    RoundedCornerShape(
                        28.dp
                    ),

                ambientColor =
                    animatedGlowColor.copy(
                        alpha = pulseAlpha
                    ),

                spotColor =
                    animatedGlowColor.copy(
                        alpha = pulseAlpha
                    )
            )
            .clip(
                RoundedCornerShape(
                    28.dp
                )
            )
            .background(

                brush =
                    style.gradient
            )
            .border(

                width = 1.4.dp,

                color =
                    animatedGlowColor.copy(
                        alpha = 0.35f
                    ),

                shape =
                    RoundedCornerShape(
                        28.dp
                    )
            )
            .padding(
                SentriXSpacing.ExtraLarge
            ),

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | LEFT ICON SECTION
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .offset(
                    y = floatingOffset.dp
                )
                .size(84.dp)
                .clip(
                    CircleShape
                )
                .background(

                    color =
                        Color.White.copy(
                            alpha = 0.12f
                        )
                )
                .border(

                    width = 1.5.dp,

                    color =
                        Color.White.copy(
                            alpha = 0.25f
                        ),

                    shape =
                        CircleShape
                ),

            contentAlignment =
                Alignment.Center
        ) {

            Icon(

                imageVector =
                    style.icon,

                contentDescription = null,

                tint = Text_Primary,

                modifier = Modifier.size(
                    IconDimensions.Huge
                )
            )
        }



        Spacer(
            modifier = Modifier.width(
                SentriXSpacing.ExtraLarge
            )
        )



        /*
        |--------------------------------------------------------------------------
        | CONTENT SECTION
        |--------------------------------------------------------------------------
        */

        Column(

            modifier = Modifier.weight(1f)
        ) {

            /*
            |--------------------------------------------------------------------------
            | LIVE STATUS
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
                            Color.White
                        )
                )

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing.Small
                    )
                )

                Text(

                    text = "LIVE PROTECTION",

                    style =
                        TerminalTypography.Body,

                    color =
                        Text_Primary
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Medium
                )
            )



            /*
            |--------------------------------------------------------------------------
            | TITLE
            |--------------------------------------------------------------------------
            */

            Text(

                text = style.title,

                style =
                    HeadlineTypography.Small,

                color =
                    Text_Primary,

                fontWeight =
                    FontWeight.ExtraBold,

                maxLines = 1,

                overflow =
                    TextOverflow.Ellipsis
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )



            /*
            |--------------------------------------------------------------------------
            | SUBTITLE
            |--------------------------------------------------------------------------
            */

            Text(

                text = style.subtitle,

                style =
                    BodyTypography.Small,

                color =
                    Text_Primary.copy(
                        alpha = 0.88f
                    )
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Large
                )
            )



            /*
            |--------------------------------------------------------------------------
            | PROTECTION SCORE
            |--------------------------------------------------------------------------
            */

            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween
            ) {

                Text(

                    text = "Protection Score",

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Primary
                )

                Text(

                    text = "$protectionScore%",

                    style =
                        SecurityTypography
                            .ThreatWarning,

                    color =
                        Text_Primary,

                    fontWeight =
                        FontWeight.Bold
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )



            /*
            |--------------------------------------------------------------------------
            | PROGRESS INDICATOR
            |--------------------------------------------------------------------------
            */

            LinearProgressIndicator(

                progress = {
                    animatedProgress
                },

                modifier = Modifier
                    .fillMaxWidth()
                    .height(10.dp)
                    .clip(
                        RoundedCornerShape(
                            100.dp
                        )
                    ),

                color =
                    Color.White,

                trackColor =
                    Color.White.copy(
                        alpha = 0.18f
                    )
            )



            /*
            |--------------------------------------------------------------------------
            | ACTION BUTTON
            |--------------------------------------------------------------------------
            */

            if (showActionButton) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Large
                    )
                )

                TextButton(

                    onClick = onActionClick,

                    modifier = Modifier
                        .clip(
                            RoundedCornerShape(
                                100.dp
                            )
                        )
                        .background(

                            color =
                                Color.White.copy(
                                    alpha = 0.14f
                                )
                        )
                        .border(

                            width = 1.dp,

                            color =
                                Color.White.copy(
                                    alpha = 0.18f
                                ),

                            shape =
                                RoundedCornerShape(
                                    100.dp
                                )
                        )
                ) {

                    Row(

                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        Text(

                            text =
                                actionButtonText,

                            style =
                                ButtonTypography
                                    .Medium,

                            color =
                                Text_Primary
                        )

                        Spacer(
                            modifier = Modifier.width(
                                SentriXSpacing
                                    .Small
                            )
                        )

                        Icon(

                            imageVector =
                                Icons.Default
                                    .ArrowForward,

                            contentDescription =
                                null,

                            tint =
                                Text_Primary
                        )
                    }
                }
            }
        }
    }
}



/* =========================================================
   MINI PROTECTION BANNER
   ========================================================= */

@Composable
fun MiniProtectionBanner(

    protectionScore: Int
) {

    LiveProtectionBanner(

        protectionScore = protectionScore,

        showActionButton = false
    )
}



/* =========================================================
   AI MONITORING BANNER
   ========================================================= */

@Composable
fun AIMonitoringBanner(

    aiConfidence: Int
) {

    LiveProtectionBanner(

        protectionState =
            ProtectionState.MONITORING,

        protectionScore = aiConfidence,

        actionButtonText =
            "Open AI Scanner"
    )
}



/* =========================================================
   THREAT ALERT BANNER
   ========================================================= */

@Composable
fun ThreatAlertBanner(

    threatScore: Int
) {

    LiveProtectionBanner(

        protectionState =
            ProtectionState.CRITICAL,

        protectionScore = threatScore,

        actionButtonText =
            "Resolve Threat"
    )
}



/* =========================================================
   FUTURE PROTECTION BANNER EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time threat streaming
| ✔ AI adaptive protection banners
| ✔ GPU holographic rendering
| ✔ Dynamic cyber-grid overlays
| ✔ Interactive threat controls
| ✔ Runtime neon animations
| ✔ Voice-assisted protection mode
| ✔ VR/AR banner rendering
| ✔ Threat prediction overlays
| ✔ Quantum security monitoring
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX LIVE PROTECTION BANNER
|--------------------------------------------------------------------------
*/
