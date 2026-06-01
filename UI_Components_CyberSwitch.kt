package com.sentrix.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Icon
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.Surface
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
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX CYBER SWITCH
|--------------------------------------------------------------------------
|
| PURPOSE:
| Futuristic enterprise toggle switch component for SentriX.
|
| FEATURES:
|
| ✔ Animated Cyber Toggle
| ✔ Neon Glow Rendering
| ✔ AI Mode Indicators
| ✔ Live Status Pulse
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Dashboard Ready
| ✔ Enterprise UX Architecture
| ✔ Dynamic Interaction Feedback
| ✔ Security Control Ready
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| CyberSwitch(
|     checked = true,
|     title = "Real-Time Protection"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SWITCH TYPES
   ========================================================= */

enum class CyberSwitchType {

    DEFAULT,

    AI,

    SECURITY,

    WARNING,

    DANGER,

    CYBERPUNK,

    NETWORK
}



/* =========================================================
   SWITCH STYLE MODEL
   ========================================================= */

data class CyberSwitchStyle(

    val activeGradient: Brush,

    val inactiveGradient: Brush,

    val activeColor: Color,

    val inactiveColor: Color,

    val thumbColor: Color,

    val icon: ImageVector
)



/* =========================================================
   SWITCH STYLE ENGINE
   ========================================================= */

object CyberSwitchEngine {

    fun style(
        type: CyberSwitchType
    ): CyberSwitchStyle {

        return when (type) {

            CyberSwitchType.DEFAULT ->

                CyberSwitchStyle(

                    activeGradient =
                        BrandGradients.Primary,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF2A2A2A),

                                Color(0xFF3A3A3A)
                            )
                        ),

                    activeColor =
                        SentriX_AccentCyan,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.ToggleOn
                )

            CyberSwitchType.AI ->

                CyberSwitchStyle(

                    activeGradient =
                        AIGradients.Neural,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF242424),

                                Color(0xFF383838)
                            )
                        ),

                    activeColor =
                        AI_Active,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.Memory
                )

            CyberSwitchType.SECURITY ->

                CyberSwitchStyle(

                    activeGradient =
                        ThreatGradients.LowThreat,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF202020),

                                Color(0xFF323232)
                            )
                        ),

                    activeColor =
                        Threat_Low,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.VerifiedUser
                )

            CyberSwitchType.WARNING ->

                CyberSwitchStyle(

                    activeGradient =
                        ThreatGradients.MediumThreat,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF2A2A2A),

                                Color(0xFF404040)
                            )
                        ),

                    activeColor =
                        Threat_Medium,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.WarningAmber
                )

            CyberSwitchType.DANGER ->

                CyberSwitchStyle(

                    activeGradient =
                        ThreatGradients.CriticalThreat,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF262626),

                                Color(0xFF393939)
                            )
                        ),

                    activeColor =
                        Threat_Critical,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.GppBad
                )

            CyberSwitchType.CYBERPUNK ->

                CyberSwitchStyle(

                    activeGradient =
                        CyberpunkGradients.Hologram,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF1E1E1E),

                                Color(0xFF2E2E2E)
                            )
                        ),

                    activeColor =
                        Color(0xFFFF00FF),

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.Bolt
                )

            CyberSwitchType.NETWORK ->

                CyberSwitchStyle(

                    activeGradient =
                        AnalyticsGradients.NetworkTraffic,

                    inactiveGradient =
                        Brush.horizontalGradient(

                            colors = listOf(

                                Color(0xFF252525),

                                Color(0xFF373737)
                            )
                        ),

                    activeColor =
                        Network_Incoming,

                    inactiveColor =
                        Text_Muted,

                    thumbColor =
                        Color.White,

                    icon =
                        Icons.Default.Wifi
                )
        }
    }
}



/* =========================================================
   MAIN CYBER SWITCH
   ========================================================= */

@Composable
fun CyberSwitch(

    modifier: Modifier = Modifier,

    checked: Boolean,

    onCheckedChange: (Boolean) -> Unit,

    title: String,

    subtitle: String = "",

    switchType: CyberSwitchType =
        CyberSwitchType.DEFAULT,

    enabled: Boolean = true,

    showPulseIndicator: Boolean = true,

    showStatusText: Boolean = true
) {

    val style =
        CyberSwitchEngine.style(
            switchType
        )



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

            initialValue = 0.3f,

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
    | FLOATING ICON ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -1.5f,

            targetValue = 1.5f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(1800),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ACTIVE COLOR ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedActiveColor by animateColorAsState(

        targetValue = if (checked)

            style.activeColor

        else

            style.inactiveColor,

        animationSpec =
            tween(400)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
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
                        24.dp
                    ),

                ambientColor =
                    animatedActiveColor.copy(

                        alpha = if (
                            checked
                        )

                            pulseAlpha

                        else

                            0.08f
                    ),

                spotColor =
                    animatedActiveColor.copy(

                        alpha = if (
                            checked
                        )

                            pulseAlpha

                        else

                            0.08f
                    )
            )
            .clip(
                RoundedCornerShape(
                    24.dp
                )
            )
            .background(

                color =
                    Background_Card
            )
            .border(

                width = 1.dp,

                color =
                    animatedActiveColor.copy(
                        alpha = 0.22f
                    ),

                shape =
                    RoundedCornerShape(
                        24.dp
                    )
            )
            .padding(
                SentriXSpacing.Large
            ),

        verticalAlignment =
            Alignment.CenterVertically
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
                .size(58.dp)
                .shadow(

                    elevation =
                        SentriXShadow.Small,

                    shape =
                        CircleShape,

                    ambientColor =
                        animatedActiveColor.copy(
                            alpha = pulseAlpha
                        )
                )
                .clip(
                    CircleShape
                )
                .background(

                    brush = if (checked)

                        style.activeGradient

                    else

                        style.inactiveGradient
                )
                .border(

                    width = 1.2.dp,

                    color =
                        animatedActiveColor.copy(
                            alpha = 0.28f
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
                    style.thumbColor,

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
        | TEXT CONTENT
        |--------------------------------------------------------------------------
        */

        Column(

            modifier = Modifier.weight(1f)
        ) {

            /*
            |--------------------------------------------------------------------------
            | TITLE ROW
            |--------------------------------------------------------------------------
            */

            Row(

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
                        FontWeight.Bold
                )



                if (
                    showPulseIndicator &&
                    checked
                ) {

                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing
                                .Small
                        )
                    )

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
                                animatedActiveColor
                            )
                    )
                }
            }



            /*
            |--------------------------------------------------------------------------
            | SUBTITLE
            |--------------------------------------------------------------------------
            */

            if (
                subtitle.isNotEmpty()
            ) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing
                            .ExtraSmall
                    )
                )

                Text(

                    text = subtitle,

                    style =
                        BodyTypography.Small,

                    color =
                        Text_Secondary
                )
            }



            /*
            |--------------------------------------------------------------------------
            | STATUS TEXT
            |--------------------------------------------------------------------------
            */

            if (showStatusText) {

                Spacer(
                    modifier = Modifier.height(
                        SentriXSpacing
                            .Small
                    )
                )

                Text(

                    text = if (checked)

                        "ACTIVE"

                    else

                        "DISABLED",

                    style =
                        TerminalTypography.Body,

                    color =
                        animatedActiveColor
                )
            }
        }



        /*
        |--------------------------------------------------------------------------
        | CUSTOM SWITCH TRACK
        |--------------------------------------------------------------------------
        */

        Box(

            modifier = Modifier
                .width(78.dp)
                .height(42.dp)
                .clip(
                    RoundedCornerShape(
                        100.dp
                    )
                )
                .background(

                    brush = if (checked)

                        style.activeGradient

                    else

                        style.inactiveGradient
                )
                .border(

                    width = 1.dp,

                    color =
                        animatedActiveColor.copy(
                            alpha = 0.22f
                        ),

                    shape =
                        RoundedCornerShape(
                            100.dp
                        )
                )
                .padding(4.dp)
        ) {

            /*
            |--------------------------------------------------------------------------
            | THUMB
            |--------------------------------------------------------------------------
            */

            Box(

                modifier = Modifier
                    .offset(

                        x = if (checked)

                            36.dp

                        else

                            0.dp
                    )
                    .size(34.dp)
                    .shadow(

                        elevation =
                            SentriXShadow.Small,

                        shape =
                            CircleShape
                    )
                    .clip(
                        CircleShape
                    )
                    .background(
                        style.thumbColor
                    )
                    .border(

                        width = 1.dp,

                        color =
                            Color.White.copy(
                                alpha = 0.22f
                            ),

                        shape =
                            CircleShape
                    )
            )
        }



        /*
        |--------------------------------------------------------------------------
        | CLICK OVERLAY
        |--------------------------------------------------------------------------
        */

        Spacer(

            modifier = Modifier
                .matchParentSize()
        )
    }



    /*
    |--------------------------------------------------------------------------
    | CLICKABLE SURFACE
    |--------------------------------------------------------------------------
    */

    Surface(

        modifier = Modifier
            .fillMaxSize(),

        color = Color.Transparent,

        onClick = {

            if (enabled) {

                onCheckedChange(
                    !checked
                )
            }
        }
    ) {}
}



/* =========================================================
   AI CYBER SWITCH
   ========================================================= */

@Composable
fun AICyberSwitch(

    checked: Boolean,

    onCheckedChange: (Boolean) -> Unit
) {

    CyberSwitch(

        checked = checked,

        onCheckedChange =
            onCheckedChange,

        title =
            "AI Monitoring",

        subtitle =
            "SentriX neural engine is actively scanning threats",

        switchType =
            CyberSwitchType.AI
    )
}



/* =========================================================
   SECURITY CYBER SWITCH
   ========================================================= */

@Composable
fun SecurityCyberSwitch(

    checked: Boolean,

    onCheckedChange: (Boolean) -> Unit
) {

    CyberSwitch(

        checked = checked,

        onCheckedChange =
            onCheckedChange,

        title =
            "Real-Time Protection",

        subtitle =
            "Continuous protection against malicious activity",

        switchType =
            CyberSwitchType.SECURITY
    )
}



/* =========================================================
   DANGER CYBER SWITCH
   ========================================================= */

@Composable
fun DangerCyberSwitch(

    checked: Boolean,

    onCheckedChange: (Boolean) -> Unit
) {

    CyberSwitch(

        checked = checked,

        onCheckedChange =
            onCheckedChange,

        title =
            "Threat Isolation",

        subtitle =
            "Automatically isolate critical threats",

        switchType =
            CyberSwitchType.DANGER
    )
}



/* =========================================================
   MINI CYBER SWITCH
   ========================================================= */

@Composable
fun MiniCyberSwitch(

    checked: Boolean,

    onCheckedChange: (Boolean) -> Unit,

    title: String
) {

    CyberSwitch(

        checked = checked,

        onCheckedChange =
            onCheckedChange,

        title = title,

        showStatusText = false,

        showPulseIndicator = false
    )
}



/* =========================================================
   FUTURE CYBER SWITCH EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive interaction engine
| ✔ GPU holographic toggle rendering
| ✔ Dynamic cyber-grid switch effects
| ✔ Runtime neural interaction system
| ✔ Voice reactive switches
| ✔ Quantum dashboard toggles
| ✔ VR/AR interaction rendering
| ✔ Gesture-controlled switches
| ✔ Threat synchronization engine
| ✔ Dynamic system intelligence
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX CYBER SWITCH
|--------------------------------------------------------------------------
*/
