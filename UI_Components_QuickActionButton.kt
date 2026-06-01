package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
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
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.graphicsLayer
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX QUICK ACTION BUTTON
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic enterprise quick-action component for SentriX.
|
| FEATURES:
|
| ✔ Premium Animated Action Buttons
| ✔ AI Security Shortcuts
| ✔ Cyberpunk Glow Effects
| ✔ Multi-State Action System
| ✔ Glassmorphism Rendering
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Enterprise UX Architecture
| ✔ Dynamic Interaction Feedback
| ✔ Expandable Action Framework
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| QuickActionButton(
|     title = "Quick Scan",
|     icon = Icons.Default.Security
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   QUICK ACTION TYPES
   ========================================================= */

enum class QuickActionType {

    PRIMARY,

    SECURITY,

    AI,

    NETWORK,

    ANALYTICS,

    DANGER,

    CYBERPUNK,

    SUCCESS
}



/* =========================================================
   BUTTON SIZES
   ========================================================= */

enum class QuickActionSize {

    MINI,

    SMALL,

    MEDIUM,

    LARGE
}



/* =========================================================
   ACTION STYLE MODEL
   ========================================================= */

data class QuickActionStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val iconColor: Color
)



/* =========================================================
   ACTION STYLE ENGINE
   ========================================================= */

object QuickActionEngine {

    fun style(
        type: QuickActionType
    ): QuickActionStyle {

        return when (type) {

            QuickActionType.PRIMARY ->

                QuickActionStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentBlue,

                    borderColor =
                        SentriX_AccentBlue,

                    iconColor =
                        Color.White
                )

            QuickActionType.SECURITY ->

                QuickActionStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    iconColor =
                        Color.White
                )

            QuickActionType.AI ->

                QuickActionStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    iconColor =
                        Color.White
                )

            QuickActionType.NETWORK ->

                QuickActionStyle(

                    gradient =
                        AnalyticsGradients.NetworkTraffic,

                    glowColor =
                        Network_Incoming,

                    borderColor =
                        Network_Incoming,

                    iconColor =
                        Color.White
                )

            QuickActionType.ANALYTICS ->

                QuickActionStyle(

                    gradient =
                        AnalyticsGradients.Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    borderColor =
                        SentriX_AccentPurple,

                    iconColor =
                        Color.White
                )

            QuickActionType.DANGER ->

                QuickActionStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    iconColor =
                        Color.White
                )

            QuickActionType.CYBERPUNK ->

                QuickActionStyle(

                    gradient =
                        CyberpunkGradients.Hologram,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    iconColor =
                        Color.White
                )

            QuickActionType.SUCCESS ->

                QuickActionStyle(

                    gradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF00C853),

                                Color(0xFF00E676)
                            )
                        ),

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    iconColor =
                        Color.White
                )
        }
    }



    fun buttonSize(
        size: QuickActionSize
    ): Pair<Int, Int> {

        return when (size) {

            QuickActionSize.MINI ->
                Pair(64, 16)

            QuickActionSize.SMALL ->
                Pair(82, 22)

            QuickActionSize.MEDIUM ->
                Pair(110, 28)

            QuickActionSize.LARGE ->
                Pair(140, 36)
        }
    }
}



/* =========================================================
   MAIN QUICK ACTION BUTTON
   ========================================================= */

@Composable
fun QuickActionButton(

    modifier: Modifier = Modifier,

    title: String,

    icon: ImageVector,

    actionType: QuickActionType =
        QuickActionType.PRIMARY,

    buttonSize: QuickActionSize =
        QuickActionSize.MEDIUM,

    enabled: Boolean = true,

    showPulse: Boolean = true,

    showGlow: Boolean = true,

    badgeText: String? = null,

    onClick: () -> Unit
) {

    val style =
        QuickActionEngine.style(
            actionType
        )



    val dimensions =
        QuickActionEngine.buttonSize(
            buttonSize
        )



    val buttonHeight = dimensions.first.dp
    val iconSize = dimensions.second.dp



    /*
    |--------------------------------------------------------------------------
    | INTERACTION SOURCE
    |--------------------------------------------------------------------------
    */

    val interactionSource =
        remember {
            MutableInteractionSource()
        }



    /*
    |--------------------------------------------------------------------------
    | LIVE ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

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
    | FLOATING EFFECT
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -2f,

            targetValue = 2f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2000),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | SCALE ANIMATION
    |--------------------------------------------------------------------------
    */

    val scaleAnimation by infiniteTransition
        .animateFloat(

            initialValue = 1f,

            targetValue = 1.02f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1800),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ENABLED COLOR
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue = if (enabled)

            style.borderColor

        else

            Text_Muted,

        animationSpec =
            tween(300)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN BUTTON
    |--------------------------------------------------------------------------
    */

    Box(

        modifier = modifier
            .graphicsLayer {

                scaleX = scaleAnimation
                scaleY = scaleAnimation
            }
            .shadow(

                elevation = if (showGlow)

                    SentriXShadow.Huge

                else

                    SentriXShadow.Small,

                shape =
                    RoundedCornerShape(
                        28.dp
                    ),

                ambientColor =
                    animatedBorderColor.copy(

                        alpha = if (
                            enabled
                        )

                            pulseAlpha * 0.6f

                        else

                            0.08f
                    ),

                spotColor =
                    animatedBorderColor.copy(

                        alpha = if (
                            enabled
                        )

                            pulseAlpha * 0.6f

                        else

                            0.08f
                    )
            )
            .clip(
                RoundedCornerShape(
                    28.dp
                )
            )
            .background(

                brush = if (enabled)

                    style.gradient

                else

                    Brush.horizontalGradient(

                        colors = listOf(

                            Color(0xFF2A2A2A),

                            Color(0xFF3A3A3A)
                        )
                    )
            )
            .border(

                width = 1.3.dp,

                color =
                    animatedBorderColor.copy(
                        alpha = 0.24f
                    ),

                shape =
                    RoundedCornerShape(
                        28.dp
                    )
            )
            .blur(0.15.dp)
            .clickable(

                enabled = enabled,

                interactionSource =
                    interactionSource,

                indication = null
            ) {

                onClick()
            }
            .padding(
                SentriXSpacing.Medium
            )
    ) {

        /*
        |--------------------------------------------------------------------------
        | BADGE
        |--------------------------------------------------------------------------
        */

        if (badgeText != null) {

            Box(

                modifier = Modifier
                    .align(
                        Alignment.TopEnd
                    )
                    .offset(
                        x = 6.dp,
                        y = (-6).dp
                    )
                    .clip(
                        RoundedCornerShape(
                            100.dp
                        )
                    )
                    .background(
                        Threat_Critical
                    )
                    .padding(

                        horizontal = 8.dp,
                        vertical = 3.dp
                    )
            ) {

                Text(

                    text = badgeText,

                    style =
                        TerminalTypography.Body,

                    color = Color.White
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | CONTENT
        |--------------------------------------------------------------------------
        */

        Column(

            modifier = Modifier
                .height(buttonHeight)
                .widthIn(min = 110.dp),

            horizontalAlignment =
                Alignment.CenterHorizontally,

            verticalArrangement =
                Arrangement.Center
        ) {

            /*
            |--------------------------------------------------------------------------
            | ICON CONTAINER
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .offset(
                        y = floatingOffset.dp
                    )
                    .size(54.dp)
                    .shadow(

                        elevation =
                            SentriXShadow.Medium,

                        shape =
                            CircleShape,

                        ambientColor =
                            animatedBorderColor.copy(
                                alpha = pulseAlpha
                            ),

                        spotColor =
                            animatedBorderColor.copy(
                                alpha = pulseAlpha
                            )
                    )
                    .clip(
                        CircleShape
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
                                alpha = 0.16f
                            ),

                        shape =
                            CircleShape
                    ),

                contentAlignment =
                    Alignment.Center
            ) {

                Icon(

                    imageVector = icon,

                    contentDescription = null,

                    tint = style.iconColor,

                    modifier = Modifier.size(
                        iconSize.dp
                    )
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

                text = title,

                style =
                    BodyTypography.Medium,

                color =
                    if (enabled)

                        Color.White

                    else

                        Text_Muted,

                fontWeight =
                    FontWeight.Bold,

                textAlign =
                    TextAlign.Center,

                maxLines = 2
            )



            /*
            |--------------------------------------------------------------------------
            | LIVE INDICATOR
            |--------------------------------------------------------------------------
            */

            if (showPulse && enabled) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Small
                    )
                )

                Row(

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    Box(

                        modifier = Modifier
                            .size(8.dp)
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
                            SentriXSpacing
                                .ExtraSmall
                        )
                    )

                    Text(

                        text = "ACTIVE",

                        style =
                            TerminalTypography
                                .Body,

                        color =
                            Color.White.copy(
                                alpha = 0.9f
                            )
                    )
                }
            }
        }
    }
}



/* =========================================================
   QUICK SCAN BUTTON
   ========================================================= */

@Composable
fun QuickScanButton(

    onClick: () -> Unit
) {

    QuickActionButton(

        title =
            "Quick Scan",

        icon =
            Icons.Default.Security,

        actionType =
            QuickActionType.SECURITY,

        onClick =
            onClick
    )
}



/* =========================================================
   AI ANALYSIS BUTTON
   ========================================================= */

@Composable
fun AIAnalysisButton(

    onClick: () -> Unit
) {

    QuickActionButton(

        title =
            "AI Analysis",

        icon =
            Icons.Default.Memory,

        actionType =
            QuickActionType.AI,

        badgeText =
            "AI",

        onClick =
            onClick
    )
}



/* =========================================================
   NETWORK MONITOR BUTTON
   ========================================================= */

@Composable
fun NetworkMonitorButton(

    onClick: () -> Unit
) {

    QuickActionButton(

        title =
            "Network\nMonitor",

        icon =
            Icons.Default.Wifi,

        actionType =
            QuickActionType.NETWORK,

        onClick =
            onClick
    )
}



/* =========================================================
   THREAT BLOCK BUTTON
   ========================================================= */

@Composable
fun ThreatBlockButton(

    onClick: () -> Unit
) {

    QuickActionButton(

        title =
            "Block\nThreats",

        icon =
            Icons.Default.GppBad,

        actionType =
            QuickActionType.DANGER,

        badgeText =
            "!"

        ,

        onClick =
            onClick
    )
}



/* =========================================================
   MINI QUICK ACTION BUTTON
   ========================================================= */

@Composable
fun MiniQuickActionButton(

    title: String,

    icon: ImageVector,

    onClick: () -> Unit
) {

    QuickActionButton(

        title = title,

        icon = icon,

        buttonSize =
            QuickActionSize.SMALL,

        showPulse = false,

        showGlow = false,

        onClick = onClick
    )
}



/* =========================================================
   FUTURE QUICK ACTION ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive action intelligence
| ✔ GPU holographic interactions
| ✔ Dynamic cyber-grid rendering
| ✔ Runtime predictive shortcuts
| ✔ Voice-controlled actions
| ✔ Quantum interaction engine
| ✔ VR/AR action rendering
| ✔ Gesture-driven controls
| ✔ Threat-aware action system
| ✔ Neural dashboard shortcuts
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX QUICK ACTION BUTTON
|--------------------------------------------------------------------------
*/
