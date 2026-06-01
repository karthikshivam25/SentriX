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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX THREAT CARD COMPONENT
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise threat visualization component for SentriX.
|
| FEATURES:
|
| ✔ Live Threat Monitoring
| ✔ Animated Threat Levels
| ✔ AI Threat Analysis
| ✔ Risk Visualization
| ✔ Threat Severity Engine
| ✔ Pulse Animations
| ✔ Rotating Scanner Effects
| ✔ Glassmorphism Ready
| ✔ Cyberpunk Compatible
| ✔ Military Compatible
| ✔ AMOLED Optimized
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| ThreatCard(
|     threatName = "Malware Injection",
|     source = "192.168.1.24",
|     severity = ThreatSeverity.CRITICAL,
|     riskScore = 94
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   THREAT SEVERITY SYSTEM
   ========================================================= */

enum class ThreatSeverity {

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL,

    SEVERE
}



/* =========================================================
   THREAT DATA MODEL
   ========================================================= */

data class ThreatData(

    val title: String,

    val description: String,

    val color: Color,

    val gradient: Brush,

    val icon: ImageVector
)



/* =========================================================
   THREAT STYLE ENGINE
   ========================================================= */

object ThreatEngine {

    fun configuration(
        severity: ThreatSeverity
    ): ThreatData {

        return when (severity) {

            ThreatSeverity.SAFE -> ThreatData(

                title = "Protected",

                description = "No active threats detected",

                color = Threat_Low,

                gradient = ThreatGradients.LowThreat,

                icon = Icons.Default.VerifiedUser
            )

            ThreatSeverity.LOW -> ThreatData(

                title = "Low Risk",

                description = "Minimal suspicious activities detected",

                color = Threat_Low,

                gradient = ThreatGradients.LowThreat,

                icon = Icons.Default.Security
            )

            ThreatSeverity.MEDIUM -> ThreatData(

                title = "Medium Risk",

                description = "Potential vulnerability identified",

                color = Threat_Medium,

                gradient = ThreatGradients.MediumThreat,

                icon = Icons.Default.WarningAmber
            )

            ThreatSeverity.HIGH -> ThreatData(

                title = "High Risk",

                description = "Suspicious system behavior detected",

                color = Threat_High,

                gradient = ThreatGradients.HighThreat,

                icon = Icons.Default.ReportProblem
            )

            ThreatSeverity.CRITICAL -> ThreatData(

                title = "Critical Threat",

                description = "Immediate security action required",

                color = Threat_Critical,

                gradient = ThreatGradients.CriticalThreat,

                icon = Icons.Default.Dangerous
            )

            ThreatSeverity.SEVERE -> ThreatData(

                title = "Severe Threat",

                description = "System integrity compromised",

                color = Threat_Severe,

                gradient = ThreatGradients.SevereThreat,

                icon = Icons.Default.GppBad
            )
        }
    }
}



/* =========================================================
   MAIN THREAT CARD
   ========================================================= */

@Composable
fun ThreatCard(

    modifier: Modifier = Modifier,

    threatName: String,

    source: String,

    severity: ThreatSeverity = ThreatSeverity.LOW,

    riskScore: Int = 0,

    detectionTime: String = "Just now",

    aiAnalysisEnabled: Boolean = true,

    enableAnimations: Boolean = true
) {

    val threatData =
        ThreatEngine.configuration(
            severity
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseScale by infiniteTransition.animateFloat(

        initialValue = 1f,

        targetValue = 1.08f,

        animationSpec = infiniteRepeatable(

            animation = tween(
                durationMillis = 800
            ),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ROTATING SCANNER EFFECT
    |--------------------------------------------------------------------------
    */

    val rotationAnimation by infiniteTransition.animateFloat(

        initialValue = 0f,

        targetValue = 360f,

        animationSpec = infiniteRepeatable(

            animation = tween(
                durationMillis = 4000,
                easing = LinearEasing
            )
        )
    )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED THREAT COLOR
    |--------------------------------------------------------------------------
    */

    val animatedColor by animateColorAsState(

        targetValue = threatData.color,

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
                elevation = SentriXShadow.Huge,
                shape = CardShapes.SecurityPanel
            )
            .clip(
                CardShapes.SecurityPanel
            )
            .background(
                brush = threatData.gradient
            )
            .border(
                width = 1.4.dp,
                brush = threatData.gradient,
                shape = CardShapes.SecurityPanel
            ),

        shape = CardShapes.SecurityPanel,

        colors = CardDefaults.cardColors(

            containerColor =
                Color(0xFF111827)
        )

    ) {

        Column(

            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    SentriXSpacing.ExtraLarge
                )
        ) {

            /*
            |--------------------------------------------------------------------------
            | TOP HEADER
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
                | THREAT ICON
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .size(68.dp)
                        .graphicsLayer {

                            if (enableAnimations) {

                                scaleX = pulseScale

                                scaleY = pulseScale
                            }
                        }
                        .clip(CircleShape)
                        .background(
                            animatedColor.copy(
                                alpha = 0.14f
                            )
                        )
                        .border(
                            width = 1.2.dp,
                            color = animatedColor,
                            shape = CircleShape
                        ),

                    contentAlignment =
                        Alignment.Center
                ) {

                    Icon(

                        imageVector = threatData.icon,

                        contentDescription = null,

                        tint = animatedColor,

                        modifier = Modifier
                            .size(
                                IconDimensions.ExtraLarge
                            )
                            .rotate(
                                if (
                                    severity ==
                                    ThreatSeverity.SEVERE
                                )
                                    rotationAnimation
                                else
                                    0f
                            )
                    )
                }



                /*
                |--------------------------------------------------------------------------
                | THREAT STATUS
                |--------------------------------------------------------------------------
                */

                Column(

                    horizontalAlignment =
                        Alignment.End
                ) {

                    Text(

                        text = threatData.title,

                        style =
                            SecurityTypography.ThreatCritical,

                        color = animatedColor
                    )

                    Spacer(
                        modifier = Modifier.height(
                            SentriXSpacing.ExtraSmall
                        )
                    )

                    Text(

                        text = detectionTime,

                        style =
                            TerminalTypography.Tiny,

                        color = Text_Secondary
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
            | THREAT DETAILS
            |--------------------------------------------------------------------------
            */

            Text(

                text = threatName,

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

                text = threatData.description,

                style = BodyTypography.Small,

                color = Text_Secondary
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Large
                )
            )



            /*
            |--------------------------------------------------------------------------
            | SOURCE INFORMATION
            |--------------------------------------------------------------------------
            */

            Row(

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                Icon(

                    imageVector = Icons.Default.Language,

                    contentDescription = null,

                    tint = animatedColor,

                    modifier = Modifier.size(
                        IconDimensions.Small
                    )
                )

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing.Small
                    )
                )

                Text(

                    text = "Source: $source",

                    style = TerminalTypography.Body,

                    color = Text_Secondary
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraLarge
                )
            )



            /*
            |--------------------------------------------------------------------------
            | RISK SCORE SECTION
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

                    text = "Risk Score",

                    style =
                        DashboardTypography.Label,

                    color = Text_Secondary
                )

                Text(

                    text = "$riskScore%",

                    style =
                        DashboardTypography.Metric,

                    color = animatedColor,

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
            | PROGRESS INDICATOR
            |--------------------------------------------------------------------------
            */

            LinearProgressIndicator(

                progress = {
                    riskScore / 100f
                },

                modifier = Modifier
                    .fillMaxWidth()
                    .height(12.dp)
                    .clip(
                        RoundedCornerShape(100.dp)
                    ),

                color = animatedColor,

                trackColor =
                    Color.White.copy(
                        alpha = 0.08f
                    )
            )



            /*
            |--------------------------------------------------------------------------
            | AI ANALYSIS SECTION
            |--------------------------------------------------------------------------
            */

            if (aiAnalysisEnabled) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.ExtraLarge
                    )
                )

                Row(

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    Box(

                        modifier = Modifier
                            .size(12.dp)
                            .alpha(
                                PulseEffects
                                    .pulseAlpha()
                            )
                            .clip(CircleShape)
                            .background(
                                AI_Active
                            )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )

                    Text(

                        text =
                            "AI Security Engine actively analyzing threat patterns",

                        style =
                            AIScannerText,

                        color = AI_Active
                    )
                }
            }
        }
    }
}



/* =========================================================
   MINI THREAT CARD
   ========================================================= */

@Composable
fun MiniThreatCard(

    modifier: Modifier = Modifier,

    title: String,

    severity: ThreatSeverity
) {

    val data =
        ThreatEngine.configuration(
            severity
        )

    Card(

        modifier = modifier,

        shape = CardShapes.Standard,

        colors = CardDefaults.cardColors(

            containerColor =
                Color(0xFF1A2338)
        )

    ) {

        Row(

            modifier = Modifier
                .padding(
                    SentriXSpacing.Medium
                ),

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            Icon(

                imageVector = data.icon,

                contentDescription = null,

                tint = data.color
            )

            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.Medium
                )
            )

            Column {

                Text(

                    text = title,

                    style = BodyTypography.Medium,

                    color = Text_Primary
                )

                Text(

                    text = data.title,

                    style = BodyTypography.Small,

                    color = data.color
                )
            }
        }
    }
}



/* =========================================================
   FUTURE THREAT CARD EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time threat streaming
| ✔ Live attack map rendering
| ✔ AI prediction overlays
| ✔ Dynamic holographic effects
| ✔ Threat heatmaps
| ✔ Interactive cyber-grid
| ✔ 3D threat visualization
| ✔ Runtime GPU acceleration
| ✔ Threat clustering engine
| ✔ Multi-device threat sync
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX THREAT CARD COMPONENT
|--------------------------------------------------------------------------
*/
