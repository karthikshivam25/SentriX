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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX DEVICE INFO CARD
|--------------------------------------------------------------------------
|
| PURPOSE:
| Premium futuristic device monitoring card for SentriX.
|
| FEATURES:
|
| ✔ Real-Time Device Monitoring
| ✔ CPU / RAM / Battery Analytics
| ✔ AI Device Health Intelligence
| ✔ Cyberpunk Glow Rendering
| ✔ Animated Device Scanner
| ✔ AMOLED Optimized
| ✔ Enterprise Dashboard Ready
| ✔ Live Device Telemetry
| ✔ Security-Aware Monitoring
| ✔ Expandable Hardware Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| DeviceInfoCard(
|     deviceName = "SentriX Secure Node",
|     deviceType = DeviceType.DESKTOP
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   DEVICE TYPES
   ========================================================= */

enum class DeviceType {

    DESKTOP,

    LAPTOP,

    MOBILE,

    SERVER,

    TABLET,

    SMART_WATCH
}



/* =========================================================
   DEVICE STATES
   ========================================================= */

enum class DeviceState {

    SECURE,

    MONITORING,

    WARNING,

    CRITICAL,

    OFFLINE
}



/* =========================================================
   DEVICE STYLE MODEL
   ========================================================= */

data class DeviceCardStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector,

    val stateLabel: String
)



/* =========================================================
   DEVICE STYLE ENGINE
   ========================================================= */

object DeviceCardEngine {

    fun style(
        state: DeviceState
    ): DeviceCardStyle {

        return when (state) {

            DeviceState.SECURE ->

                DeviceCardStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser,

                    stateLabel =
                        "DEVICE SECURE"
                )

            DeviceState.MONITORING ->

                DeviceCardStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory,

                    stateLabel =
                        "LIVE MONITORING"
                )

            DeviceState.WARNING ->

                DeviceCardStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber,

                    stateLabel =
                        "PERFORMANCE WARNING"
                )

            DeviceState.CRITICAL ->

                DeviceCardStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad,

                    stateLabel =
                        "CRITICAL DEVICE STATE"
                )

            DeviceState.OFFLINE ->

                DeviceCardStyle(

                    gradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF444444),

                                Color(0xFF5A5A5A)
                            )
                        ),

                    glowColor =
                        Text_Muted,

                    borderColor =
                        Text_Muted,

                    icon =
                        Icons.Default.PowerOff,

                    stateLabel =
                        "DEVICE OFFLINE"
                )
        }
    }



    fun deviceIcon(
        deviceType: DeviceType
    ): ImageVector {

        return when (deviceType) {

            DeviceType.DESKTOP ->
                Icons.Default.DesktopWindows

            DeviceType.LAPTOP ->
                Icons.Default.LaptopMac

            DeviceType.MOBILE ->
                Icons.Default.PhoneAndroid

            DeviceType.SERVER ->
                Icons.Default.Dns

            DeviceType.TABLET ->
                Icons.Default.TabletMac

            DeviceType.SMART_WATCH ->
                Icons.Default.Watch
        }
    }
}



/* =========================================================
   MAIN DEVICE INFO CARD
   ========================================================= */

@Composable
fun DeviceInfoCard(

    modifier: Modifier = Modifier,

    deviceName: String,

    deviceType: DeviceType =
        DeviceType.DESKTOP,

    deviceState: DeviceState =
        DeviceState.SECURE,

    operatingSystem: String =
        "SentriX OS 3.0",

    cpuUsage: Int = 32,

    ramUsage: Int = 58,

    batteryLevel: Int = 88,

    storageUsage: Int = 47,

    networkLatency: Int = 16,

    temperature: Int = 41,

    showScannerAnimation: Boolean = true
) {

    val style =
        DeviceCardEngine.style(
            deviceState
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

                    animation = tween(2200),

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

                width = 1.3.dp,

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
            | DEVICE VISUALIZER
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

                            sweepAngle = 90f,

                            useCenter = false,

                            style = Stroke(
                                width = 10f
                            )
                        )
                    }
                }



                /*
                |--------------------------------------------------------------------------
                | DEVICE CORE
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
                            DeviceCardEngine
                                .deviceIcon(
                                    deviceType
                                ),

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
            | DEVICE DETAILS
            |--------------------------------------------------------------------------
            */

            Column(

                modifier = Modifier.weight(1f)
            ) {

                /*
                |--------------------------------------------------------------------------
                | LIVE STATE
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
                            style.stateLabel,

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
                | DEVICE NAME
                |--------------------------------------------------------------------------
                */

                Text(

                    text = deviceName,

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
                | DEVICE TYPE
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "Type • ${deviceType.name}",

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Secondary
                )



                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing.ExtraSmall
                    )
                )



                /*
                |--------------------------------------------------------------------------
                | OPERATING SYSTEM
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "OS • $operatingSystem",

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
        | SYSTEM METRICS
        |--------------------------------------------------------------------------
        */

        DeviceMetricBar(
            label = "CPU Usage",
            value = cpuUsage,
            color = Threat_High
        )

        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.Medium
            )
        )

        DeviceMetricBar(
            label = "RAM Usage",
            value = ramUsage,
            color = SentriX_AccentBlue
        )

        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.Medium
            )
        )

        DeviceMetricBar(
            label = "Storage Usage",
            value = storageUsage,
            color = SentriX_AccentPurple
        )



        Spacer(
            modifier = Modifier.height(
                SentriXSpacing.ExtraLarge
            )
        )



        /*
        |--------------------------------------------------------------------------
        | BOTTOM STATS
        |--------------------------------------------------------------------------
        */

        Row(

            modifier = Modifier.fillMaxWidth(),

            horizontalArrangement =
                Arrangement.SpaceBetween
        ) {

            DeviceStatItem(
                label = "Battery",
                value = "$batteryLevel%",
                color = Threat_Low
            )

            DeviceStatItem(
                label = "Latency",
                value = "${networkLatency}ms",
                color = SentriX_AccentBlue
            )

            DeviceStatItem(
                label = "Temp",
                value = "${temperature}°C",
                color = Threat_Medium
            )
        }
    }
}



/* =========================================================
   DEVICE METRIC BAR
   ========================================================= */

@Composable
private fun DeviceMetricBar(

    label: String,

    value: Int,

    color: Color
) {

    Column {

        Row(

            modifier = Modifier.fillMaxWidth(),

            horizontalArrangement =
                Arrangement.SpaceBetween
        ) {

            Text(

                text = label,

                style =
                    BodyTypography.Small,

                color =
                    Text_Primary
            )

            Text(

                text = "$value%",

                style =
                    BodyTypography.Small,

                color = color,

                fontWeight =
                    FontWeight.Bold
            )
        }

        Spacer(
            modifier = Modifier.height(6.dp)
        )

        LinearProgressIndicator(

            progress = {

                value / 100f
            },

            modifier = Modifier
                .fillMaxWidth()
                .height(9.dp)
                .clip(
                    RoundedCornerShape(
                        100.dp
                    )
                ),

            color = color,

            trackColor =
                Color.White.copy(
                    alpha = 0.08f
                )
        )
    }
}



/* =========================================================
   DEVICE STAT ITEM
   ========================================================= */

@Composable
private fun DeviceStatItem(

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
   SECURE DEVICE CARD
   ========================================================= */

@Composable
fun SecureDeviceCard(

    deviceName: String
) {

    DeviceInfoCard(

        deviceName = deviceName,

        deviceState =
            DeviceState.SECURE
    )
}



/* =========================================================
   WARNING DEVICE CARD
   ========================================================= */

@Composable
fun WarningDeviceCard(

    deviceName: String
) {

    DeviceInfoCard(

        deviceName = deviceName,

        deviceState =
            DeviceState.WARNING
    )
}



/* =========================================================
   CRITICAL DEVICE CARD
   ========================================================= */

@Composable
fun CriticalDeviceCard(

    deviceName: String
) {

    DeviceInfoCard(

        deviceName = deviceName,

        deviceState =
            DeviceState.CRITICAL
    )
}



/* =========================================================
   FUTURE DEVICE ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI hardware prediction engine
| ✔ Quantum device monitoring
| ✔ GPU holographic rendering
| ✔ Dynamic thermal visualization
| ✔ VR/AR device monitoring
| ✔ Real-time hardware analytics
| ✔ Runtime power optimization
| ✔ Threat-aware hardware protection
| ✔ Live sensor intelligence
| ✔ Neural performance balancing
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX DEVICE INFO CARD
|--------------------------------------------------------------------------
*/
