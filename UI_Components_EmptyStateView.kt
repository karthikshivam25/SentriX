package com.sentrix.ui.components

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
| SENTRIX EMPTY STATE VIEW
|--------------------------------------------------------------------------
|
| PURPOSE:
| Premium futuristic empty-state UI component for SentriX.
|
| FEATURES:
|
| ✔ AI Empty-State Visualization
| ✔ Animated Floating Icon
| ✔ Cyberpunk Glow Effects
| ✔ Gradient Rendering
| ✔ Glassmorphism Compatible
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Reusable Architecture
| ✔ Enterprise UX System
| ✔ AI Monitoring Visual States
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| EmptyStateView(
|     title = "No Threats Detected",
|     description = "Your system is currently secure"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   EMPTY STATE TYPES
   ========================================================= */

enum class EmptyStateType {

    DEFAULT,

    SECURITY,

    AI,

    ANALYTICS,

    SEARCH,

    NETWORK,

    THREAT,

    CYBERPUNK
}



/* =========================================================
   EMPTY STATE STYLE MODEL
   ========================================================= */

data class EmptyStateStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector
)



/* =========================================================
   EMPTY STATE ENGINE
   ========================================================= */

object EmptyStateEngine {

    fun style(
        type: EmptyStateType
    ): EmptyStateStyle {

        return when (type) {

            EmptyStateType.DEFAULT ->

                EmptyStateStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    borderColor =
                        SentriX_AccentCyan,

                    icon =
                        Icons.Default.Inbox
                )

            EmptyStateType.SECURITY ->

                EmptyStateStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser
                )

            EmptyStateType.AI ->

                EmptyStateStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory
                )

            EmptyStateType.ANALYTICS ->

                EmptyStateStyle(

                    gradient =
                        AnalyticsGradients.Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    borderColor =
                        SentriX_AccentPurple,

                    icon =
                        Icons.Default.Analytics
                )

            EmptyStateType.SEARCH ->

                EmptyStateStyle(

                    gradient =
                        GlassGradients.PremiumGlass,

                    glowColor =
                        SentriX_AccentBlue,

                    borderColor =
                        SentriX_AccentBlue,

                    icon =
                        Icons.Default.SearchOff
                )

            EmptyStateType.NETWORK ->

                EmptyStateStyle(

                    gradient =
                        AnalyticsGradients.NetworkTraffic,

                    glowColor =
                        Network_Incoming,

                    borderColor =
                        Network_Incoming,

                    icon =
                        Icons.Default.WifiOff
                )

            EmptyStateType.THREAT ->

                EmptyStateStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            EmptyStateType.CYBERPUNK ->

                EmptyStateStyle(

                    gradient =
                        CyberpunkGradients.Hologram,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    icon =
                        Icons.Default.Bolt
                )
        }
    }
}



/* =========================================================
   MAIN EMPTY STATE VIEW
   ========================================================= */

@Composable
fun EmptyStateView(

    modifier: Modifier = Modifier,

    title: String,

    description: String,

    emptyStateType: EmptyStateType =
        EmptyStateType.DEFAULT,

    showActionButton: Boolean = false,

    actionButtonText: String = "Refresh",

    onActionClick: () -> Unit = {}
) {

    val style =
        EmptyStateEngine.style(
            emptyStateType
        )



    /*
    |--------------------------------------------------------------------------
    | FLOATING ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -8f,

            targetValue = 8f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



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

                    animation = tween(1200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Column(

        modifier = modifier
            .fillMaxWidth()
            .padding(
                SentriXSpacing.ExtraLarge
            ),

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
                .graphicsLayer {

                    translationY =
                        floatingOffset
                }
                .size(160.dp)
                .shadow(

                    elevation =
                        SentriXShadow.Huge,

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

                    width = 1.5.dp,

                    color =
                        style.borderColor.copy(
                            alpha = 0.32f
                        ),

                    shape =
                        CircleShape
                ),

            contentAlignment =
                Alignment.Center
        ) {

            /*
            |--------------------------------------------------------------------------
            | INNER GLOW CIRCLE
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(120.dp)
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
            | ICON
            |--------------------------------------------------------------------------
            */

            Icon(

                imageVector =
                    style.icon,

                contentDescription = null,

                tint =
                    Text_Primary,

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
                        style.glowColor
                    )
            )

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Small
                )
            )

            Text(

                text = "SYSTEM STATUS",

                style =
                    TerminalTypography.Body,

                color =
                    style.glowColor
            )
        }



        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.Large
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
                HeadlineTypography.Medium,

            color =
                Text_Primary,

            fontWeight =
                FontWeight.ExtraBold,

            textAlign =
                TextAlign.Center
        )



        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.Medium
            )
        )



        /*
        |--------------------------------------------------------------------------
        | DESCRIPTION
        |--------------------------------------------------------------------------
        */

        Text(

            text = description,

            style =
                BodyTypography.Medium,

            color =
                Text_Secondary,

            textAlign =
                TextAlign.Center
        )



        /*
        |--------------------------------------------------------------------------
        | ACTION BUTTON
        |--------------------------------------------------------------------------
        */

        if (showActionButton) {

            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraLarge
                )
            )

            AnimatedGradientButton(

                text = actionButtonText,

                onClick = onActionClick,

                buttonType =
                    GradientButtonType.PRIMARY,

                fullWidth = false
            )
        }
    }
}



/* =========================================================
   SECURITY EMPTY VIEW
   ========================================================= */

@Composable
fun SecurityEmptyView(

    title: String =
        "No Threats Detected",

    description: String =
        "Your SentriX protection engine reports a fully secure system"
) {

    EmptyStateView(

        title = title,

        description = description,

        emptyStateType =
            EmptyStateType.SECURITY
    )
}



/* =========================================================
   AI EMPTY VIEW
   ========================================================= */

@Composable
fun AIEmptyView(

    title: String =
        "AI Engine Waiting",

    description: String =
        "SentriX AI is ready to analyze incoming system activity"
) {

    EmptyStateView(

        title = title,

        description = description,

        emptyStateType =
            EmptyStateType.AI
    )
}



/* =========================================================
   SEARCH EMPTY VIEW
   ========================================================= */

@Composable
fun SearchEmptyView(

    title: String =
        "No Results Found",

    description: String =
        "SentriX search engine could not find matching records"
) {

    EmptyStateView(

        title = title,

        description = description,

        emptyStateType =
            EmptyStateType.SEARCH
    )
}



/* =========================================================
   NETWORK EMPTY VIEW
   ========================================================= */

@Composable
fun NetworkEmptyView(

    title: String =
        "No Network Activity",

    description: String =
        "No active traffic or suspicious packets detected"
) {

    EmptyStateView(

        title = title,

        description = description,

        emptyStateType =
            EmptyStateType.NETWORK
    )
}



/* =========================================================
   FUTURE EMPTY STATE ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive empty states
| ✔ GPU holographic rendering
| ✔ Dynamic cyber-grid overlays
| ✔ Runtime emotional UI engine
| ✔ Quantum dashboard placeholders
| ✔ VR/AR empty-state rendering
| ✔ Voice assistant integration
| ✔ Interactive onboarding flows
| ✔ AI predictive recommendations
| ✔ Dynamic security storytelling
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX EMPTY STATE VIEW
|--------------------------------------------------------------------------
*/
