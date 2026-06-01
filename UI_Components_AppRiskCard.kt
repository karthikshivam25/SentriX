package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
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
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX APP RISK CARD
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise-grade application risk intelligence card for SentriX.
|
| FEATURES:
|
| ✔ AI Risk Analysis
| ✔ Permission Threat Detection
| ✔ Real-Time App Monitoring
| ✔ Malware Probability Visualization
| ✔ Cyberpunk Glow Rendering
| ✔ Animated Threat Scanner
| ✔ AMOLED Optimized
| ✔ Enterprise Dashboard Ready
| ✔ Security-Aware Analytics
| ✔ Expandable Threat Intelligence Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| AppRiskCard(
|     appName = "Chrome",
|     riskLevel = AppRiskLevel.LOW
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   APP RISK LEVELS
   ========================================================= */

enum class AppRiskLevel {

    SAFE,

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}



/* =========================================================
   APP MONITOR STATES
   ========================================================= */

enum class AppMonitorState {

    ACTIVE,

    ANALYZING,

    BLOCKED,

    QUARANTINED,

    TRUSTED
}



/* =========================================================
   APP RISK STYLE MODEL
   ========================================================= */

data class AppRiskStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector,

    val riskLabel: String
)



/* =========================================================
   APP RISK STYLE ENGINE
   ========================================================= */

object AppRiskEngine {

    fun style(
        riskLevel: AppRiskLevel
    ): AppRiskStyle {

        return when (riskLevel) {

            AppRiskLevel.SAFE ->

                AppRiskStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser,

                    riskLabel =
                        "APPLICATION VERIFIED"
                )

            AppRiskLevel.LOW ->

                AppRiskStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentBlue,

                    borderColor =
                        SentriX_AccentBlue,

                    icon =
                        Icons.Default.Security,

                    riskLabel =
                        "LOW RISK DETECTED"
                )

            AppRiskLevel.MEDIUM ->

                AppRiskStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber,

                    riskLabel =
                        "MEDIUM RISK ANALYSIS"
                )

            AppRiskLevel.HIGH ->

                AppRiskStyle(

                    gradient =
                        ThreatGradients.HighThreat,

                    glowColor =
                        Threat_High,

                    borderColor =
                        Threat_High,

                    icon =
                        Icons.Default.ReportProblem,

                    riskLabel =
                        "HIGH RISK APPLICATION"
                )

            AppRiskLevel.CRITICAL ->

                AppRiskStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad,

                    riskLabel =
                        "CRITICAL SECURITY THREAT"
                )
        }
    }
}



/* =========================================================
   MAIN APP RISK CARD
   ========================================================= */

@Composable
fun AppRiskCard(

    modifier: Modifier = Modifier,

    appName: String,

    packageName: String = "com.sentrix.app",

    riskLevel: AppRiskLevel =
        AppRiskLevel.LOW,

    monitorState: AppMonitorState =
        AppMonitorState.ACTIVE,

    riskScore: Int = 28,

    permissionsUsed: Int = 14,

    suspiciousActivities: Int = 0,

    networkConnections: Int = 3,

    batteryUsage: Int = 9,

    aiConfidence: Int = 96,

    lastScanned: String = "Just Now",

    showScannerAnimation: Boolean = true
) {

    val style =
        AppRiskEngine.style(
            riskLevel
        )



    /*
    |--------------------------------------------------------------------------
    | LIVE ANIMATION ENGINE
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()



    /*
    |--------------------------------------------------------------------------
    | RADAR ROTATION
    |--------------------------------------------------------------------------
    */

    val radarRotation by infiniteTransition
        .animateFloat(

            initialValue = 0f,

            targetValue = 360f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(

                        durationMillis = 5000,

                        easing = LinearEasing
                    )
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PULSE EFFECT
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
    | FLOATING CORE
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -3f,

            targetValue = 3f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2400),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | BORDER COLOR
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue =
            style.borderColor,

        animationSpec =
            tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CARD
    |--------------------------------------------------------------------------
    */

    Column(

        modifier = modifier
            .fillMaxWidth()
            .shadow(

                elevation =
                    SentriXShadow.Huge,

                shape =
                    RoundedCornerShape(
                        32.dp
                    ),

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
                RoundedCornerShape(
                    32.dp
                )
            )
            .background(
                Background_Card
            )
            .border(

                width = 1.4.dp,

                color =
                    animatedBorderColor.copy(
                        alpha = 0.28f
                    ),

                shape =
                    RoundedCornerShape(
                        32.dp
                    )
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

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            /*
            |--------------------------------------------------------------------------
            | APP VISUALIZER
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .size(120.dp),

                contentAlignment =
                    Alignment.Center
            ) {

                /*
                |--------------------------------------------------------------------------
                | RADAR SCANNER
                |--------------------------------------------------------------------------
                */

                if (showScannerAnimation) {

                    Canvas(

                        modifier = Modifier
                            .fillMaxSize()
                            .rotate(
                                radarRotation
                            )
                    ) {

                        drawArc(

                            brush =
                                Brush.sweepGradient(

                                    colors = listOf(

                                        Color.Transparent,

                                        style.glowColor,

                                        Color.Transparent
                                    )
                                ),

                            startAngle = 0f,

                            sweepAngle = 100f,

                            useCenter = false,

                            style = Stroke(
                                width = 10f
                            )
                        )
                    }
                }



                /*
                |--------------------------------------------------------------------------
                | MAIN APP CORE
                |--------------------------------------------------------------------------
                */

                Box(

                    modifier = Modifier
                        .offset(
                            y = floatingOffset.dp
                        )
                        .size(82.dp)
                        .shadow(

                            elevation =
                                SentriXShadow.Huge,

                            shape =
                                CircleShape,

                            ambientColor =
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

                            width = 1.2.dp,

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
                modifier = Modifier.width(
                    SentriXSpacing.ExtraLarge
                )
            )



            /*
            |--------------------------------------------------------------------------
            | APP DETAILS
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
                                style.glowColor
                            )
                    )

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )

                    Text(

                        text =
                            style.riskLabel,

                        style =
                            TerminalTypography.Body,

                        color =
                            style.glowColor
                    )
                }



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.Small
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | APP NAME
                |--------------------------------------------------------------------------
                */

                Text(

                    text = appName,

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
                | PACKAGE NAME
                |--------------------------------------------------------------------------
                */

                Text(

                    text = packageName,

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Secondary,

                    maxLines = 1,

                    overflow =
                        TextOverflow.Ellipsis
                )



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.ExtraSmall
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | MONITOR STATE
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "State • ${monitorState.name}",

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Secondary
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
        | AI RISK SCORE
        |--------------------------------------------------------------------------
        */

        Column {

            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween
            ) {

                Text(

                    text =
                        "AI Risk Score",

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Primary
                )

                Text(

                    text =
                        "$riskScore%",

                    style =
                        BodyTypography.Small,

                    color =
                        style.glowColor,

                    fontWeight =
                        FontWeight.Bold
                )
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )



            LinearProgressIndicator(

                progress = {

                    riskScore / 100f
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
                    style.glowColor,

                trackColor =
                    Color.White.copy(
                        alpha = 0.08f
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
        | ANALYTICS GRID
        |--------------------------------------------------------------------------
        */

        Row(

            modifier = Modifier.fillMaxWidth(),

            horizontalArrangement =
                Arrangement.SpaceBetween
        ) {

            AppRiskMetricItem(
                label = "Permissions",
                value = permissionsUsed.toString(),
                color = SentriX_AccentBlue
            )

            AppRiskMetricItem(
                label = "Suspicious",
                value = suspiciousActivities.toString(),
                color = Threat_Critical
            )

            AppRiskMetricItem(
                label = "Connections",
                value = networkConnections.toString(),
                color = Threat_Low
            )

            AppRiskMetricItem(
                label = "Battery",
                value = "$batteryUsage%",
                color = Threat_Medium
            )
        }



        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.ExtraLarge
            )
        )



        /*
        |--------------------------------------------------------------------------
        | FOOTER SECTION
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
            | LAST SCANNED
            |--------------------------------------------------------------------------
            */

            Text(

                text =
                    "Scanned • $lastScanned",

                style =
                    TerminalTypography.Body,

                color =
                    Text_Muted
            )



            /*
            |--------------------------------------------------------------------------
            | AI CONFIDENCE
            |--------------------------------------------------------------------------
            */

            Row(

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                Box(

                    modifier = Modifier
                        .size(8.dp)
                        .clip(
                            CircleShape
                        )
                        .background(
                            style.glowColor
                        )
                )

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing
                            .ExtraSmall
                    )
                )

                Text(

                    text =
                        "AI • $aiConfidence%",

                    style =
                        TerminalTypography.Body,

                    color =
                        style.glowColor
                )
            }
        }
    }
}



/* =========================================================
   APP METRIC ITEM
   ========================================================= */

@Composable
private fun AppRiskMetricItem(

    label: String,

    value: String,

    color: Color
) {

    Column(

        horizontalAlignment =
            Alignment.CenterHorizontally
    ) {

        Text(

            text = value,

            style =
                BodyTypography.Medium,

            color = color,

            fontWeight =
                FontWeight.ExtraBold
        )

        Spacer(
            modifier = Modifier.height(4.dp)
        )

        Text(

            text = label,

            style =
                TerminalTypography.Body,

            color =
                Text_Secondary
        )
    }
}



/* =========================================================
   SAFE APP CARD
   ========================================================= */

@Composable
fun SafeAppRiskCard(

    appName: String
) {

    AppRiskCard(

        appName = appName,

        riskLevel =
            AppRiskLevel.SAFE,

        riskScore = 6
    )
}



/* =========================================================
   WARNING APP CARD
   ========================================================= */

@Composable
fun WarningAppRiskCard(

    appName: String
) {

    AppRiskCard(

        appName = appName,

        riskLevel =
            AppRiskLevel.MEDIUM,

        riskScore = 48
    )
}



/* =========================================================
   CRITICAL APP CARD
   ========================================================= */

@Composable
fun CriticalAppRiskCard(

    appName: String
) {

    AppRiskCard(

        appName = appName,

        riskLevel =
            AppRiskLevel.CRITICAL,

        riskScore = 94,

        suspiciousActivities = 7
    )
}



/* =========================================================
   FUTURE APP RISK ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI behavioral threat prediction
| ✔ Quantum malware analysis
| ✔ GPU holographic rendering
| ✔ Live permission tracking
| ✔ Dynamic app intelligence engine
| ✔ VR/AR threat visualization
| ✔ Runtime behavioral learning
| ✔ Threat-aware battery optimization
| ✔ Neural network app scoring
| ✔ Global malware intelligence feed
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX APP RISK CARD
|--------------------------------------------------------------------------
*/
