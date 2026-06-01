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
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX NOTIFICATION CARD
|--------------------------------------------------------------------------
|
| PURPOSE:
| Premium futuristic notification component system for SentriX.
|
| FEATURES:
|
| ✔ Live Notification Engine
| ✔ AI Security Alerts
| ✔ Animated Glow Effects
| ✔ Threat Severity Indicators
| ✔ Glassmorphism Support
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Cyberpunk Compatible
| ✔ Enterprise Alert System
| ✔ Expandable Notification Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| NotificationCard(
|     title = "Threat Blocked",
|     message = "Malicious script execution prevented"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   NOTIFICATION TYPES
   ========================================================= */

enum class NotificationType {

    DEFAULT,

    SUCCESS,

    WARNING,

    DANGER,

    AI,

    NETWORK,

    CYBERPUNK,

    UPDATE
}



/* =========================================================
   PRIORITY LEVELS
   ========================================================= */

enum class NotificationPriority {

    LOW,

    MEDIUM,

    HIGH,

    CRITICAL
}



/* =========================================================
   STYLE MODEL
   ========================================================= */

data class NotificationCardStyle(

    val gradient: Brush,

    val glowColor: Color,

    val borderColor: Color,

    val icon: ImageVector
)



/* =========================================================
   STYLE ENGINE
   ========================================================= */

object NotificationCardEngine {

    fun style(
        type: NotificationType
    ): NotificationCardStyle {

        return when (type) {

            NotificationType.DEFAULT ->

                NotificationCardStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    borderColor =
                        SentriX_AccentBlue,

                    icon =
                        Icons.Default.Notifications
                )

            NotificationType.SUCCESS ->

                NotificationCardStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    borderColor =
                        Threat_Low,

                    icon =
                        Icons.Default.VerifiedUser
                )

            NotificationType.WARNING ->

                NotificationCardStyle(

                    gradient =
                        ThreatGradients.MediumThreat,

                    glowColor =
                        Threat_Medium,

                    borderColor =
                        Threat_Medium,

                    icon =
                        Icons.Default.WarningAmber
                )

            NotificationType.DANGER ->

                NotificationCardStyle(

                    gradient =
                        ThreatGradients.CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    borderColor =
                        Threat_Critical,

                    icon =
                        Icons.Default.GppBad
                )

            NotificationType.AI ->

                NotificationCardStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    borderColor =
                        AI_Active,

                    icon =
                        Icons.Default.Memory
                )

            NotificationType.NETWORK ->

                NotificationCardStyle(

                    gradient =
                        AnalyticsGradients.NetworkTraffic,

                    glowColor =
                        Network_Incoming,

                    borderColor =
                        Network_Incoming,

                    icon =
                        Icons.Default.Wifi
                )

            NotificationType.CYBERPUNK ->

                NotificationCardStyle(

                    gradient =
                        CyberpunkGradients.Hologram,

                    glowColor =
                        Color(0xFFFF00FF),

                    borderColor =
                        Color(0xFFFF00FF),

                    icon =
                        Icons.Default.Bolt
                )

            NotificationType.UPDATE ->

                NotificationCardStyle(

                    gradient =
                        AnalyticsGradients.Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    borderColor =
                        SentriX_AccentPurple,

                    icon =
                        Icons.Default.SystemUpdate
                )
        }
    }
}



/* =========================================================
   MAIN NOTIFICATION CARD
   ========================================================= */

@Composable
fun NotificationCard(

    modifier: Modifier = Modifier,

    title: String,

    message: String,

    timestamp: String = "Just Now",

    notificationType: NotificationType =
        NotificationType.DEFAULT,

    priority: NotificationPriority =
        NotificationPriority.MEDIUM,

    isUnread: Boolean = true,

    showCloseButton: Boolean = true,

    onClose: () -> Unit = {},

    onClick: () -> Unit = {}
) {

    val style =
        NotificationCardEngine.style(
            notificationType
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
    | PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val pulseAlpha by infiniteTransition
        .animateFloat(

            initialValue = 0.35f,

            targetValue = 1f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1100),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PRIORITY GLOW
    |--------------------------------------------------------------------------
    */

    val glowStrength by infiniteTransition
        .animateFloat(

            initialValue = 0.15f,

            targetValue = 0.45f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1800),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | PRIORITY COLOR
    |--------------------------------------------------------------------------
    */

    val priorityColor = when (priority) {

        NotificationPriority.LOW ->
            Threat_Low

        NotificationPriority.MEDIUM ->
            SentriX_AccentBlue

        NotificationPriority.HIGH ->
            Threat_High

        NotificationPriority.CRITICAL ->
            Threat_Critical
    }



    /*
    |--------------------------------------------------------------------------
    | ANIMATED BORDER
    |--------------------------------------------------------------------------
    */

    val animatedBorderColor by animateColorAsState(

        targetValue = if (isUnread)

            priorityColor

        else

            style.borderColor.copy(
                alpha = 0.22f
            ),

        animationSpec =
            tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CARD
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .fillMaxWidth()
            .shadow(

                elevation =
                    SentriXShadow.Medium,

                shape =
                    RoundedCornerShape(
                        28.dp
                    ),

                ambientColor =
                    priorityColor.copy(
                        alpha = glowStrength
                    ),

                spotColor =
                    priorityColor.copy(
                        alpha = glowStrength
                    )
            )
            .clip(
                RoundedCornerShape(
                    28.dp
                )
            )
            .background(
                Background_Card
            )
            .border(

                width = 1.2.dp,

                color =
                    animatedBorderColor,

                shape =
                    RoundedCornerShape(
                        28.dp
                    )
            )
            .padding(
                SentriXSpacing.Large
            ),

        verticalAlignment =
            Alignment.Top
    ) {

        /*
        |--------------------------------------------------------------------------
        | ICON CONTAINER
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .size(64.dp)
                .shadow(

                    elevation =
                        SentriXShadow.Small,

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

                    width = 1.dp,

                    color =
                        Color.White.copy(
                            alpha = 0.18f
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
                    IconDimensions.Large
                )
            )
        }



        Spacer(
            modifier = Modifier.width(
                SentriXSpacing.Large
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
            | TOP ROW
            |--------------------------------------------------------------------------
            */

            Row(

                modifier = Modifier
                    .fillMaxWidth(),

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                Text(

                    text = title,

                    style =
                        BodyTypography.Large,

                    color =
                        Text_Primary,

                    fontWeight =
                        FontWeight.ExtraBold,

                    modifier = Modifier.weight(1f),

                    maxLines = 1,

                    overflow =
                        TextOverflow.Ellipsis
                )



                /*
                |--------------------------------------------------------------------------
                | UNREAD INDICATOR
                |--------------------------------------------------------------------------
                */

                if (isUnread) {

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
                                priorityColor
                            )
                    )
                }



                /*
                |--------------------------------------------------------------------------
                | CLOSE BUTTON
                |--------------------------------------------------------------------------
                */

                if (showCloseButton) {

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing
                                .Small
                        )
                    )

                    IconButton(

                        onClick = onClose
                    ) {

                        Box(

                            modifier = Modifier
                                .size(34.dp)
                                .clip(
                                    CircleShape
                                )
                                .background(

                                    color =
                                        Background_Secondary
                                ),

                            contentAlignment =
                                Alignment.Center
                        ) {

                            Icon(

                                imageVector =
                                    Icons.Default.Close,

                                contentDescription =
                                    "Close",

                                tint =
                                    Text_Secondary
                            )
                        }
                    }
                }
            }



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Small
                )
            )



            /*
            |--------------------------------------------------------------------------
            | MESSAGE
            |--------------------------------------------------------------------------
            */

            Text(

                text = message,

                style =
                    BodyTypography.Medium,

                color =
                    Text_Secondary,

                maxLines = 3,

                overflow =
                    TextOverflow.Ellipsis
            )



            Spacer(
                modifier = Modifier.height(
                    SentriXSpacing.Medium
                )
            )



            /*
            |--------------------------------------------------------------------------
            | FOOTER
            |--------------------------------------------------------------------------
            */

            Row(

                modifier = Modifier
                    .fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween,

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                /*
                |--------------------------------------------------------------------------
                | TIMESTAMP
                |--------------------------------------------------------------------------
                */

                Text(

                    text = timestamp,

                    style =
                        TerminalTypography.Body,

                    color =
                        Text_Muted
                )



                /*
                |--------------------------------------------------------------------------
                | PRIORITY BADGE
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
                                priorityColor
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
                            priority.name,

                        style =
                            TerminalTypography
                                .Body,

                        color =
                            priorityColor
                    )
                }
            }
        }
    }
}



/* =========================================================
   SUCCESS NOTIFICATION
   ========================================================= */

@Composable
fun SuccessNotificationCard(

    title: String,

    message: String
) {

    NotificationCard(

        title = title,

        message = message,

        notificationType =
            NotificationType.SUCCESS,

        priority =
            NotificationPriority.LOW
    )
}



/* =========================================================
   DANGER NOTIFICATION
   ========================================================= */

@Composable
fun DangerNotificationCard(

    title: String,

    message: String
) {

    NotificationCard(

        title = title,

        message = message,

        notificationType =
            NotificationType.DANGER,

        priority =
            NotificationPriority.CRITICAL
    )
}



/* =========================================================
   AI NOTIFICATION
   ========================================================= */

@Composable
fun AINotificationCard(

    title: String,

    message: String
) {

    NotificationCard(

        title = title,

        message = message,

        notificationType =
            NotificationType.AI,

        priority =
            NotificationPriority.HIGH
    )
}



/* =========================================================
   NETWORK NOTIFICATION
   ========================================================= */

@Composable
fun NetworkNotificationCard(

    title: String,

    message: String
) {

    NotificationCard(

        title = title,

        message = message,

        notificationType =
            NotificationType.NETWORK,

        priority =
            NotificationPriority.MEDIUM
    )
}



/* =========================================================
   FUTURE NOTIFICATION ENGINE EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive notification engine
| ✔ GPU holographic alerts
| ✔ Real-time threat synchronization
| ✔ Dynamic cyber-grid overlays
| ✔ Runtime alert intelligence
| ✔ VR/AR notification rendering
| ✔ Voice-assisted alert system
| ✔ Quantum notification streams
| ✔ Interactive analytics alerts
| ✔ Global threat broadcasting
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX NOTIFICATION CARD
|--------------------------------------------------------------------------
*/
