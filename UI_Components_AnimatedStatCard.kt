package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
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
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX ANIMATED STAT CARD
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise animated analytics card component for SentriX.
|
| FEATURES:
|
| ✔ Animated Statistics
| ✔ AI Dashboard Visualization
| ✔ Cybersecurity Metrics
| ✔ Gradient Rendering
| ✔ Pulse Glow Effects
| ✔ Real-time Status Indicators
| ✔ Smooth Counter Animation
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Responsive Layout
| ✔ Glassmorphism Ready
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| AnimatedStatCard(
|     title = "Blocked Attacks",
|     value = 1248,
|     trendValue = "+12%",
|     cardType = StatCardType.SUCCESS
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   STAT CARD TYPES
   ========================================================= */

enum class StatCardType {

    PRIMARY,

    SUCCESS,

    WARNING,

    DANGER,

    AI,

    NETWORK,

    ANALYTICS
}



/* =========================================================
   STAT CARD STYLE DATA
   ========================================================= */

data class StatCardStyle(

    val gradient: Brush,

    val iconColor: Color,

    val glowColor: Color,

    val icon: ImageVector
)



/* =========================================================
   STAT CARD STYLE ENGINE
   ========================================================= */

object StatCardEngine {

    fun style(
        type: StatCardType
    ): StatCardStyle {

        return when (type) {

            StatCardType.PRIMARY -> StatCardStyle(

                gradient =
                    BrandGradients.Primary,

                iconColor =
                    SentriX_AccentCyan,

                glowColor =
                    SentriX_AccentCyan,

                icon =
                    Icons.Default.Dashboard
            )

            StatCardType.SUCCESS -> StatCardStyle(

                gradient =
                    ThreatGradients.LowThreat,

                iconColor =
                    Threat_Low,

                glowColor =
                    Threat_Low,

                icon =
                    Icons.Default.VerifiedUser
            )

            StatCardType.WARNING -> StatCardStyle(

                gradient =
                    ThreatGradients.MediumThreat,

                iconColor =
                    Threat_Medium,

                glowColor =
                    Threat_Medium,

                icon =
                    Icons.Default.Warning
            )

            StatCardType.DANGER -> StatCardStyle(

                gradient =
                    ThreatGradients.CriticalThreat,

                iconColor =
                    Threat_Critical,

                glowColor =
                    Threat_Critical,

                icon =
                    Icons.Default.GppBad
            )

            StatCardType.AI -> StatCardStyle(

                gradient =
                    AIGradients.Neural,

                iconColor =
                    AI_Active,

                glowColor =
                    AI_Active,

                icon =
                    Icons.Default.Memory
            )

            StatCardType.NETWORK -> StatCardStyle(

                gradient =
                    AnalyticsGradients.Traffic,

                iconColor =
                    Network_Incoming,

                glowColor =
                    Network_Incoming,

                icon =
                    Icons.Default.Language
            )

            StatCardType.ANALYTICS -> StatCardStyle(

                gradient =
                    DashboardGradients.AnalyticsCard,

                iconColor =
                    SentriX_AccentPurple,

                glowColor =
                    SentriX_AccentPurple,

                icon =
                    Icons.Default.Analytics
            )
        }
    }
}



/* =========================================================
   MAIN ANIMATED STAT CARD
   ========================================================= */

@Composable
fun AnimatedStatCard(

    modifier: Modifier = Modifier,

    title: String,

    value: Int,

    trendValue: String,

    cardType: StatCardType =
        StatCardType.PRIMARY,

    description: String = "",

    progressValue: Float = 0.8f,

    animated: Boolean = true,

    showLivePulse: Boolean = true
) {

    val style =
        StatCardEngine.style(
            cardType
        )



    /*
    |--------------------------------------------------------------------------
    | COUNTER ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedCounter by animateIntAsState(

        targetValue = value,

        animationSpec = tween(

            durationMillis = 1800,

            easing = FastOutSlowInEasing
        )
    )



    /*
    |--------------------------------------------------------------------------
    | PROGRESS ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedProgress by animateFloatAsState(

        targetValue = progressValue,

        animationSpec = tween(

            durationMillis = 1400
        )
    )



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseAlpha by infiniteTransition.animateFloat(

        initialValue = 0.4f,

        targetValue = 1f,

        animationSpec = infiniteRepeatable(

            animation = tween(1000),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ICON FLOAT ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition.animateFloat(

        initialValue = -3f,

        targetValue = 3f,

        animationSpec = infiniteRepeatable(

            animation = tween(1800),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED GLOW COLOR
    |--------------------------------------------------------------------------
    */

    val animatedGlowColor by animateColorAsState(

        targetValue = style.glowColor,

        animationSpec = tween(500)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CARD
    |--------------------------------------------------------------------------
    */

    Card(

        modifier = modifier
            .fillMaxWidth()
            .shadow(

                elevation =
                    SentriXShadow.Large,

                shape =
                    CardShapes.Premium,

                ambientColor =
                    animatedGlowColor.copy(
                        alpha = pulseAlpha
                    ),

                spotColor =
                    animatedGlowColor.copy(
                        alpha = pulseAlpha
                    )
            )
            .border(

                width = 1.2.dp,

                brush = style.gradient,

                shape =
                    CardShapes.Premium
            ),

        shape = CardShapes.Premium,

        colors = CardDefaults.cardColors(

            containerColor =
                Background_Card
        )

    ) {

        Column(

            modifier = Modifier
                .fillMaxWidth()
                .background(

                    brush =
                        GlassGradients
                            .PremiumGlass
                )
                .padding(
                    SentriXSpacing.ExtraLarge
                )
        ) {

            /*
            |--------------------------------------------------------------------------
            | TOP SECTION
            |--------------------------------------------------------------------------
            */

            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween,

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                /*
                |--------------------------------------------------------------------------
                | TITLE SECTION
                |--------------------------------------------------------------------------
                */

                Column {

                    Text(

                        text = title,

                        style =
                            DashboardTypography
                                .WidgetTitle,

                        color =
                            Text_Primary
                    )

                    Spacer(
                        modifier = Modifier.height(
                            SentriXSpacing
                                .ExtraSmall
                        )
                    )

                    Text(

                        text = trendValue,

                        style =
                            BodyTypography.Small,

                        color =
                            style.iconColor
                    )
                }



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
                        .size(62.dp)
                        .clip(CircleShape)
                        .background(

                            color =
                                style.iconColor.copy(
                                    alpha = 0.14f
                                )
                        )
                        .border(

                            width = 1.dp,

                            color =
                                style.iconColor,

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

                        tint =
                            style.iconColor,

                        modifier = Modifier.size(
                            IconDimensions
                                .Large
                        )
                    )
                }
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing
                        .ExtraLarge
                )
            )



            /*
            |--------------------------------------------------------------------------
            | VALUE SECTION
            |--------------------------------------------------------------------------
            */

            Row(

                verticalAlignment =
                    Alignment.Bottom
            ) {

                Text(

                    text =
                        animatedCounter.toString(),

                    style =
                        DashboardTypography
                            .Metric,

                    color =
                        Text_Primary,

                    fontWeight =
                        FontWeight.ExtraBold
                )

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing.Small
                    )
                )

                if (showLivePulse) {

                    Box(

                        modifier = Modifier
                            .padding(
                                bottom = 8.dp
                            )
                            .size(10.dp)
                            .alpha(
                                pulseAlpha
                            )
                            .clip(
                                CircleShape
                            )
                            .background(
                                style.iconColor
                            )
                    )
                }
            }



            /*
            |--------------------------------------------------------------------------
            | DESCRIPTION
            |--------------------------------------------------------------------------
            */

            if (description.isNotEmpty()) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing
                            .Medium
                    )
                )

                Text(

                    text = description,

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Secondary
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing
                        .Large
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
                        ButtonShapes.Pill
                    ),

                color =
                    style.iconColor,

                trackColor =
                    Color.White.copy(
                        alpha = 0.08f
                    )
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing
                        .Medium
                )
            )



            /*
            |--------------------------------------------------------------------------
            | ANALYTICS FOOTER
            |--------------------------------------------------------------------------
            */

            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween,

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                Text(

                    text = "Live Analytics",

                    style =
                        TerminalTypography.Body,

                    color =
                        Text_Secondary
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
                                style.iconColor
                            )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing
                                .Small
                        )
                    )

                    Text(

                        text = "ACTIVE",

                        style =
                            TerminalTypography.Body,

                        color =
                            style.iconColor
                    )
                }
            }
        }
    }
}



/* =========================================================
   MINI ANALYTICS CARD
   ========================================================= */

@Composable
fun MiniStatCard(

    title: String,

    value: Int,

    cardType: StatCardType
) {

    AnimatedStatCard(

        title = title,

        value = value,

        trendValue = "+0%",

        cardType = cardType,

        progressValue = 0.7f
    )
}



/* =========================================================
   AI ANALYTICS CARD
   ========================================================= */

@Composable
fun AIAnalyticsCard(

    aiProcesses: Int
) {

    AnimatedStatCard(

        title = "AI Analysis",

        value = aiProcesses,

        trendValue = "+18%",

        cardType = StatCardType.AI,

        description =
            "Neural security engine actively monitoring anomalies",

        progressValue = 0.92f
    )
}



/* =========================================================
   NETWORK ANALYTICS CARD
   ========================================================= */

@Composable
fun NetworkAnalyticsCard(

    blockedRequests: Int
) {

    AnimatedStatCard(

        title = "Blocked Requests",

        value = blockedRequests,

        trendValue = "+32%",

        cardType = StatCardType.NETWORK,

        description =
            "Suspicious traffic blocked by firewall engine",

        progressValue = 0.88f
    )
}



/* =========================================================
   FUTURE STAT CARD EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Live streaming analytics
| ✔ AI prediction overlays
| ✔ GPU accelerated rendering
| ✔ Holographic metric cards
| ✔ Runtime dashboard widgets
| ✔ Dynamic cyber-grid rendering
| ✔ 3D analytics visualization
| ✔ VR dashboard rendering
| ✔ Adaptive enterprise layouts
| ✔ Quantum analytics engine
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX ANIMATED STAT CARD
|--------------------------------------------------------------------------
*/
