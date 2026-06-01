package com.sentrix.ui.components

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
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX SECURITY CARD COMPONENT
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise security monitoring widget for SentriX.
|
| FEATURES:
|
| ✔ Threat Monitoring
| ✔ AI Detection Status
| ✔ Live Security Metrics
| ✔ Animated Threat Pulse
| ✔ Dynamic Threat Levels
| ✔ Enterprise Dashboard Support
| ✔ Cyberpunk Compatible
| ✔ AMOLED Compatible
| ✔ Responsive Layout
| ✔ Glassmorphism Ready
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| SecurityCard(
|     title = "Firewall Protection",
|     description = "System firewall actively monitoring traffic",
|     threatLevel = ThreatLevel.SAFE,
|     percentage = 92
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   THREAT LEVEL SYSTEM
   ========================================================= */

enum class ThreatLevel {

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}



/* =========================================================
   THREAT CONFIGURATION
   ========================================================= */

data class ThreatConfiguration(

    val title: String,

    val color: Color,

    val gradient: Brush,

    val icon: androidx.compose.ui.graphics.vector.ImageVector
)



/* =========================================================
   THREAT STYLE MANAGER
   ========================================================= */

object ThreatStyleManager {

    fun configuration(
        level: ThreatLevel
    ): ThreatConfiguration {

        return when (level) {

            ThreatLevel.SAFE -> ThreatConfiguration(

                title = "Protected",

                color = Threat_Low,

                gradient = ThreatGradients.LowThreat,

                icon = Icons.Default.Verified
            )

            ThreatLevel.LOW -> ThreatConfiguration(

                title = "Low Risk",

                color = Threat_Low,

                gradient = ThreatGradients.LowThreat,

                icon = Icons.Default.Security
            )

            ThreatLevel.MEDIUM -> ThreatConfiguration(

                title = "Medium Risk",

                color = Threat_Medium,

                gradient = ThreatGradients.MediumThreat,

                icon = Icons.Default.Warning
            )

            ThreatLevel.HIGH -> ThreatConfiguration(

                title = "High Risk",

                color = Threat_High,

                gradient = ThreatGradients.HighThreat,

                icon = Icons.Default.Report
            )

            ThreatLevel.CRITICAL -> ThreatConfiguration(

                title = "Critical Threat",

                color = Threat_Critical,

                gradient = ThreatGradients.CriticalThreat,

                icon = Icons.Default.Dangerous
            )
        }
    }
}



/* =========================================================
   MAIN SECURITY CARD
   ========================================================= */

@Composable
fun SecurityCard(

    modifier: Modifier = Modifier,

    title: String,

    description: String,

    threatLevel: ThreatLevel = ThreatLevel.SAFE,

    percentage: Int = 100,

    showLiveIndicator: Boolean = true,

    enablePulseAnimation: Boolean = true
) {

    val threatConfig =
        ThreatStyleManager.configuration(
            threatLevel
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val animatedAlpha by infiniteTransition.animateFloat(

        initialValue = 0.5f,

        targetValue = 1f,

        animationSpec = infiniteRepeatable(

            animation = tween(1000),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | CARD CONTAINER
    |--------------------------------------------------------------------------
    */

    Card(

        modifier = modifier
            .fillMaxWidth()
            .height(
                CardDimensions.DashboardHeight
            )
            .shadow(
                elevation = SentriXShadow.Large,
                shape = CardShapes.Premium
            )
            .clip(
                CardShapes.Premium
            )
            .background(
                brush = DashboardGradients.AnalyticsCard
            )
            .border(
                width = 1.2.dp,
                brush = threatConfig.gradient,
                shape = CardShapes.Premium
            ),

        shape = CardShapes.Premium,

        colors = CardDefaults.cardColors(

            containerColor = Color.Transparent
        )

    ) {

        /*
        |--------------------------------------------------------------------------
        | CONTENT LAYOUT
        |--------------------------------------------------------------------------
        */

        Column(

            modifier = Modifier
                .fillMaxSize()
                .padding(
                    SentriXSpacing.ExtraLarge
                ),

            verticalArrangement =
                Arrangement.SpaceBetween
        ) {

            /*
            |--------------------------------------------------------------------------
            | HEADER
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
                | ICON SECTION
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .size(58.dp)
                        .clip(CircleShape)
                        .background(
                            threatConfig.color.copy(
                                alpha = 0.18f
                            )
                        )
                        .border(
                            width = 1.dp,
                            color = threatConfig.color,
                            shape = CircleShape
                        ),

                    contentAlignment =
                        Alignment.Center
                ) {

                    Icon(

                        imageVector = threatConfig.icon,

                        contentDescription = null,

                        tint = threatConfig.color,

                        modifier = Modifier.size(
                            IconDimensions.Large
                        )
                    )
                }



                /*
                |--------------------------------------------------------------------------
                | LIVE INDICATOR
                |--------------------------------------------------------------------------
                */

                if (showLiveIndicator) {

                    Row(

                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        Box(

                            modifier = Modifier
                                .size(10.dp)
                                .alpha(
                                    if (enablePulseAnimation)
                                        animatedAlpha
                                    else
                                        1f
                                )
                                .clip(CircleShape)
                                .background(
                                    threatConfig.color
                                )
                        )

                        Spacer(
                            modifier = Modifier.width(
                                SentriXSpacing.Small
                            )
                        )

                        Text(

                            text = "LIVE",

                            style = TerminalTypography.Body,

                            color = threatConfig.color
                        )
                    }
                }
            }



            /*
            |--------------------------------------------------------------------------
            | TITLE SECTION
            |--------------------------------------------------------------------------
            */

            Column {

                Text(

                    text = title,

                    style =
                        DashboardTypography.WidgetTitle,

                    color = Text_Primary
                )

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Small
                    )
                )

                Text(

                    text = description,

                    style = BodyTypography.Small,

                    color = Text_Secondary
                )
            }



            /*
            |--------------------------------------------------------------------------
            | SECURITY METRICS
            |--------------------------------------------------------------------------
            */

            Column {

                Row(

                    modifier = Modifier.fillMaxWidth(),

                    horizontalArrangement =
                        Arrangement.SpaceBetween
                ) {

                    Text(

                        text = threatConfig.title,

                        style =
                            SecurityTypography.ThreatWarning,

                        color = threatConfig.color
                    )

                    Text(

                        text = "$percentage%",

                        style =
                            DashboardTypography.Metric,

                        color = Text_Primary,

                        fontWeight = FontWeight.ExtraBold
                    )
                }

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Medium
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | PROGRESS BAR
                |--------------------------------------------------------------------------
                */

                LinearProgressIndicator(

                    progress = {
                        percentage / 100f
                    },

                    modifier = Modifier
                        .fillMaxWidth()
                        .height(10.dp)
                        .clip(
                            RoundedCornerShape(100.dp)
                        ),

                    color = threatConfig.color,

                    trackColor =
                        Color.White.copy(
                            alpha = 0.12f
                        )
                )
            }
        }
    }
}



/* =========================================================
   AI SECURITY CARD
   ========================================================= */

@Composable
fun AISecurityCard(

    modifier: Modifier = Modifier,

    aiStatus: String,

    aiConfidence: Int
) {

    SecurityCard(

        modifier = modifier,

        title = "AI Threat Detection",

        description =
            "Neural engine actively scanning system activities",

        threatLevel = when {

            aiConfidence >= 90 ->
                ThreatLevel.SAFE

            aiConfidence >= 70 ->
                ThreatLevel.LOW

            aiConfidence >= 50 ->
                ThreatLevel.MEDIUM

            aiConfidence >= 30 ->
                ThreatLevel.HIGH

            else ->
                ThreatLevel.CRITICAL
        },

        percentage = aiConfidence
    )
}



/* =========================================================
   FIREWALL SECURITY CARD
   ========================================================= */

@Composable
fun FirewallSecurityCard(

    modifier: Modifier = Modifier,

    firewallStrength: Int
) {

    SecurityCard(

        modifier = modifier,

        title = "Firewall Protection",

        description =
            "Monitoring incoming and outgoing network traffic",

        threatLevel = when {

            firewallStrength >= 90 ->
                ThreatLevel.SAFE

            firewallStrength >= 70 ->
                ThreatLevel.LOW

            firewallStrength >= 50 ->
                ThreatLevel.MEDIUM

            firewallStrength >= 30 ->
                ThreatLevel.HIGH

            else ->
                ThreatLevel.CRITICAL
        },

        percentage = firewallStrength
    )
}



/* =========================================================
   FUTURE SECURITY CARD EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time threat streaming
| ✔ AI generated threat reports
| ✔ Interactive analytics
| ✔ Holographic security panels
| ✔ Dynamic cyber-grid overlays
| ✔ Runtime animation engine
| ✔ GPU accelerated visualizations
| ✔ Multi-device synchronization
| ✔ Threat heatmaps
| ✔ Live attack visualization
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX SECURITY CARD
|--------------------------------------------------------------------------
*/
