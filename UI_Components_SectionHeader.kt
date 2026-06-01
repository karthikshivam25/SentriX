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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
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
| SENTRIX SECTION HEADER
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise reusable section header component for SentriX.
|
| FEATURES:
|
| ✔ Premium Dashboard Headers
| ✔ AI Status Indicators
| ✔ Live Monitoring Pulse
| ✔ Gradient Rendering
| ✔ Optional Action Buttons
| ✔ Glassmorphism Compatible
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Responsive Layout
| ✔ Enterprise Dashboard Architecture
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| SectionHeader(
|     title = "Threat Analytics",
|     subtitle = "Real-time attack monitoring"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   SECTION HEADER TYPES
   ========================================================= */

enum class SectionHeaderType {

    DEFAULT,

    AI,

    SECURITY,

    ANALYTICS,

    CYBERPUNK,

    WARNING,

    DANGER
}



/* =========================================================
   HEADER STYLE MODEL
   ========================================================= */

data class SectionHeaderStyle(

    val gradient: Brush,

    val glowColor: Color,

    val textColor: Color,

    val icon: ImageVector
)



/* =========================================================
   SECTION HEADER ENGINE
   ========================================================= */

object SectionHeaderEngine {

    fun style(
        type: SectionHeaderType
    ): SectionHeaderStyle {

        return when (type) {

            SectionHeaderType.DEFAULT ->

                SectionHeaderStyle(

                    gradient =
                        BrandGradients.Primary,

                    glowColor =
                        SentriX_AccentCyan,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.GridView
                )

            SectionHeaderType.AI ->

                SectionHeaderStyle(

                    gradient =
                        AIGradients.Neural,

                    glowColor =
                        AI_Active,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Memory
                )

            SectionHeaderType.SECURITY ->

                SectionHeaderStyle(

                    gradient =
                        ThreatGradients.LowThreat,

                    glowColor =
                        Threat_Low,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.VerifiedUser
                )

            SectionHeaderType.ANALYTICS ->

                SectionHeaderStyle(

                    gradient =
                        AnalyticsGradients.Traffic,

                    glowColor =
                        SentriX_AccentPurple,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Analytics
                )

            SectionHeaderType.CYBERPUNK ->

                SectionHeaderStyle(

                    gradient =
                        CyberpunkGradients
                            .NeonPurple,

                    glowColor =
                        Color(0xFFFF00FF),

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.Bolt
                )

            SectionHeaderType.WARNING ->

                SectionHeaderStyle(

                    gradient =
                        ThreatGradients
                            .MediumThreat,

                    glowColor =
                        Threat_Medium,

                    textColor =
                        Text_Dark,

                    icon =
                        Icons.Default.WarningAmber
                )

            SectionHeaderType.DANGER ->

                SectionHeaderStyle(

                    gradient =
                        ThreatGradients
                            .CriticalThreat,

                    glowColor =
                        Threat_Critical,

                    textColor =
                        Text_Primary,

                    icon =
                        Icons.Default.GppBad
                )
        }
    }
}



/* =========================================================
   MAIN SECTION HEADER
   ========================================================= */

@Composable
fun SectionHeader(

    modifier: Modifier = Modifier,

    title: String,

    subtitle: String = "",

    sectionType: SectionHeaderType =
        SectionHeaderType.DEFAULT,

    showLiveIndicator: Boolean = true,

    showActionButton: Boolean = false,

    actionText: String = "View All",

    onActionClick: () -> Unit = {},

    trailingIcon: ImageVector? = null
) {

    val style =
        SectionHeaderEngine.style(
            sectionType
        )



    /*
    |--------------------------------------------------------------------------
    | LIVE PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

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
    | ICON FLOAT ANIMATION
    |--------------------------------------------------------------------------
    */

    val floatingOffset by infiniteTransition
        .animateFloat(

            initialValue = -2f,

            targetValue = 2f,

            animationSpec =
                infiniteRepeatable(

                    animation = tween(2200),

                    repeatMode =
                        RepeatMode.Reverse
                )
        )



    /*
    |--------------------------------------------------------------------------
    | ANIMATED GLOW COLOR
    |--------------------------------------------------------------------------
    */

    val animatedGlowColor by animateColorAsState(

        targetValue =
            style.glowColor,

        animationSpec =
            tween(500)
    )



    /*
    |--------------------------------------------------------------------------
    | MAIN HEADER ROW
    |--------------------------------------------------------------------------
    */

    Row(

        modifier = modifier
            .fillMaxWidth(),

        horizontalArrangement =
            Arrangement.SpaceBetween,

        verticalAlignment =
            Alignment.CenterVertically
    ) {

        /*
        |--------------------------------------------------------------------------
        | LEFT CONTENT
        |--------------------------------------------------------------------------
        */

        Row(

            modifier = Modifier.weight(1f),

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
                    .offset(
                        y = floatingOffset.dp
                    )
                    .size(62.dp)
                    .shadow(

                        elevation =
                            SentriXShadow.Medium,

                        shape =
                            CircleShape,

                        ambientColor =
                            animatedGlowColor.copy(
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
                                alpha = 0.16f
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

                    contentDescription = null,

                    tint =
                        style.textColor,

                    modifier = Modifier.size(
                        IconDimensions.Large
                    )
                )
            }



            Spacer(
                modifier = Modifier.width(
                    SentriXSpacing.ExtraLarge
                )
            )



            /*
            |--------------------------------------------------------------------------
            | TITLE SECTION
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
                            HeadlineTypography
                                .Small,

                        color =
                            Text_Primary,

                        fontWeight =
                            FontWeight.ExtraBold,

                        maxLines = 1,

                        overflow =
                            TextOverflow.Ellipsis
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | LIVE INDICATOR
                    |--------------------------------------------------------------------------
                    */

                    if (showLiveIndicator) {

                        Spacer(
                            modifier = Modifier.width(
                                SentriXSpacing
                                    .Medium
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
                                    animatedGlowColor
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
                            BodyTypography
                                .Small,

                        color =
                            Text_Secondary,

                        maxLines = 2,

                        overflow =
                            TextOverflow.Ellipsis
                    )
                }
            }
        }



        /*
        |--------------------------------------------------------------------------
        | RIGHT ACTIONS
        |--------------------------------------------------------------------------
        */

        Row(

            verticalAlignment =
                Alignment.CenterVertically
        ) {

            /*
            |--------------------------------------------------------------------------
            | TRAILING ICON
            |--------------------------------------------------------------------------
            */

            if (trailingIcon != null) {

                IconButton(

                    onClick = {}
                ) {

                    Box(

                        modifier = Modifier
                            .size(48.dp)
                            .clip(
                                CircleShape
                            )
                            .background(

                                color =
                                    Background_Secondary
                            )
                            .border(

                                width = 1.dp,

                                color =
                                    animatedGlowColor
                                        .copy(
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
                                trailingIcon,

                            contentDescription =
                                null,

                            tint =
                                animatedGlowColor
                        )
                    }
                }
            }



            /*
            |--------------------------------------------------------------------------
            | ACTION BUTTON
            |--------------------------------------------------------------------------
            */

            if (showActionButton) {

                Spacer(
                    modifier = Modifier.width(
                        SentriXSpacing.Small
                    )
                )

                TextButton(

                    onClick = onActionClick,

                    modifier = Modifier
                        .clip(
                            RoundedCornerShape(
                                100.dp
                            )
                        )
                        .background(

                            brush =
                                style.gradient
                        )
                        .border(

                            width = 1.dp,

                            color =
                                animatedGlowColor
                                    .copy(
                                        alpha = 0.25f
                                    ),

                            shape =
                                RoundedCornerShape(
                                    100.dp
                                )
                        )
                ) {

                    Row(

                        verticalAlignment =
                            Alignment.CenterVertically
                    ) {

                        Text(

                            text = actionText,

                            style =
                                ButtonTypography
                                    .Medium,

                            color =
                                style.textColor,

                            fontWeight =
                                FontWeight.Bold
                        )

                        Spacer(
                            modifier = Modifier.width(
                                SentriXSpacing
                                    .Small
                            )
                        )

                        Icon(

                            imageVector =
                                Icons.Default
                                    .ArrowForward,

                            contentDescription =
                                null,

                            tint =
                                style.textColor,

                            modifier = Modifier.size(
                                IconDimensions
                                    .Small
                            )
                        )
                    }
                }
            }
        }
    }
}



/* =========================================================
   MINI SECTION HEADER
   ========================================================= */

@Composable
fun MiniSectionHeader(

    title: String
) {

    SectionHeader(

        title = title,

        showLiveIndicator = false
    )
}



/* =========================================================
   AI SECTION HEADER
   ========================================================= */

@Composable
fun AISectionHeader(

    title: String,

    subtitle: String
) {

    SectionHeader(

        title = title,

        subtitle = subtitle,

        sectionType =
            SectionHeaderType.AI
    )
}



/* =========================================================
   SECURITY SECTION HEADER
   ========================================================= */

@Composable
fun SecuritySectionHeader(

    title: String,

    subtitle: String
) {

    SectionHeader(

        title = title,

        subtitle = subtitle,

        sectionType =
            SectionHeaderType.SECURITY
    )
}



/* =========================================================
   DANGER SECTION HEADER
   ========================================================= */

@Composable
fun DangerSectionHeader(

    title: String,

    subtitle: String
) {

    SectionHeader(

        title = title,

        subtitle = subtitle,

        sectionType =
            SectionHeaderType.DANGER
    )
}



/* =========================================================
   FUTURE SECTION HEADER EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ AI adaptive section rendering
| ✔ GPU neon header rendering
| ✔ Dynamic holographic headers
| ✔ Runtime cyber-grid effects
| ✔ Interactive analytics controls
| ✔ Quantum dashboard sections
| ✔ VR/AR dashboard rendering
| ✔ Voice reactive headers
| ✔ Live attack stream headers
| ✔ Dynamic workspace sections
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX SECTION HEADER
|--------------------------------------------------------------------------
*/
