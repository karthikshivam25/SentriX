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
| SENTRIX VPN STATUS CARD
|--------------------------------------------------------------------------
|
| PURPOSE:
| Premium futuristic VPN monitoring card for SentriX.
|
| FEATURES:
|
| ✔ Real-Time VPN Monitoring
| ✔ Live Encryption Status
| ✔ AI Threat Protection State
| ✔ Cyberpunk Glow Effects
| ✔ Animated Secure Tunnel Scanner
| ✔ Glassmorphism Compatible
| ✔ AMOLED Optimized
| ✔ Enterprise Security Dashboard
| ✔ Global Network Visualization
| ✔ Expandable VPN Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| VPNStatusCard(
|     vpnEnabled = true,
|     serverLocation = "Singapore"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   VPN CONNECTION STATES
   ========================================================= */

enum class VPNConnectionState {

    CONNECTED,

    CONNECTING,

    DISCONNECTED,

    LIMITED,

    THREAT_DETECTED
}



/* =========================================================
   VPN PROTOCOL TYPES
   ========================================================= */

enum class VPNProtocol {

    WIREGUARD,

    OPENVPN,

    IKEV2,

    SENTRIX_SECURE_CORE
}



/* =========================================================
   VPN STYLE MODEL
   ========================================================= */

data class VPNStatusStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector,

    val statusLabel: String
)



/* =========================================================
   VPN STYLE ENGINE
   ========================================================= */

object VPNStatusEngine {

    fun style(
        state: VPNConnectionState
    ): VPNStatusStyle {

        return when (state) {

            VPNConnectionState.CONNECTED ->

                VPNStatusStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.Shield,

                    statusLabel =
                        "SECURE CONNECTION"
                )

            VPNConnectionState.CONNECTING ->

                VPNStatusStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    icon =
                        Icons.Default.Sync,

                    statusLabel =
                        "ESTABLISHING TUNNEL"
                )

            VPNConnectionState.DISCONNECTED ->

                VPNStatusStyle(

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
                        Icons.Default.PortableWifiOff,

                    statusLabel =
                        "VPN DISCONNECTED"
                )

            VPNConnectionState.LIMITED ->

                VPNStatusStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber,

                    statusLabel =
                        "LIMITED PROTECTION"
                )

            VPNConnectionState.THREAT_DETECTED ->

                VPNStatusStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad,

                    statusLabel =
                        "NETWORK THREAT DETECTED"
                )
        }
    }
}



/* =========================================================
   MAIN VPN STATUS CARD
   ========================================================= */

@Composable
fun VPNStatusCard(

    modifier: Modifier = Modifier,

    connectionState: VPNConnectionState =
        VPNConnectionState.CONNECTED,

    protocol: VPNProtocol =
        VPNProtocol.SENTRIX_SECURE_CORE,

    serverLocation: String =
        "Singapore",

    ipAddress: String =
        "192.168.1.14",

    encryptedTrafficPercent: Int = 94,

    pingMs: Int = 18,

    downloadSpeed: String = "148 Mbps",

    uploadSpeed: String = "62 Mbps",

    showTrafficStats: Boolean = true,

    showScannerAnimation: Boolean = true
) {

    val style =
        VPNStatusEngine.style(
            connectionState
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
    | ROTATING RADAR
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
    | STATUS COLOR
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
        | TOP STATUS SECTION
        |--------------------------------------------------------------------------
        */

        Row(

            modifier = Modifier.fillMaxWidth(),

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            /*
            |--------------------------------------------------------------------------
            | VPN CORE VISUALIZER
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
                | MAIN CORE
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
            | VPN DETAILS
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
                            style.statusLabel,

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
                | LOCATION
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "Server • $serverLocation",

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
                | PROTOCOL
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "Protocol • ${protocol.name}",

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
                | IP ADDRESS
                |--------------------------------------------------------------------------
                */

                Text(

                    text =
                        "IP • $ipAddress",

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
        | ENCRYPTION PROGRESS
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
                        "Encrypted Traffic",

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Primary
                )

                Text(

                    text =
                        "$encryptedTrafficPercent%",

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

                    encryptedTrafficPercent / 100f
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



        /*
        |--------------------------------------------------------------------------
        | TRAFFIC STATS
        |--------------------------------------------------------------------------
        */

        if (showTrafficStats) {

            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.ExtraLarge
                )
            )



            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween
            ) {

                VPNStatItem(
                    label = "Ping",
                    value = "$pingMs ms",
                    color = style.glowColor
                )

                VPNStatItem(
                    label = "Download",
                    value = downloadSpeed,
                    color = Threat_Low
                )

                VPNStatItem(
                    label = "Upload",
                    value = uploadSpeed,
                    color = SentriX_AccentBlue
                )
            }
        }
    }
}



/* =========================================================
   VPN STAT ITEM
   ========================================================= */

@Composable
private fun VPNStatItem(

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
   CONNECTED VPN CARD
   ========================================================= */

@Composable
fun ConnectedVPNCard(

    serverLocation: String
) {

    VPNStatusCard(

        connectionState =
            VPNConnectionState.CONNECTED,

        serverLocation =
            serverLocation
    )
}



/* =========================================================
   CONNECTING VPN CARD
   ========================================================= */

@Composable
fun ConnectingVPNCard() {

    VPNStatusCard(

        connectionState =
            VPNConnectionState.CONNECTING
    )
}



/* =========================================================
   THREAT VPN CARD
   ========================================================= */

@Composable
fun ThreatVPNCard() {

    VPNStatusCard(

        connectionState =
            VPNConnectionState.THREAT_DETECTED
    )
}



/* =========================================================
   FUTURE VPN ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive VPN routing
| ✔ Quantum encrypted tunnels
| ✔ GPU holographic rendering
| ✔ Dynamic global threat maps
| ✔ Real-time latency optimization
| ✔ VR/AR network visualization
| ✔ Runtime AI traffic balancing
| ✔ Threat-aware smart routing
| ✔ Live packet intelligence
| ✔ Military-grade stealth engine
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX VPN STATUS CARD
|--------------------------------------------------------------------------
*/
