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
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.Surface
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX PREMIUM TOP BAR
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise-grade premium top navigation system for SentriX.
|
| FEATURES:
|
| ✔ Premium Glassmorphism Design
| ✔ Live Security Status
| ✔ AI Monitoring Indicator
| ✔ Notification System
| ✔ Profile Management
| ✔ Search Action
| ✔ Dynamic Theme Awareness
| ✔ Cyberpunk Compatible
| ✔ AMOLED Optimized
| ✔ Enterprise Dashboard Ready
| ✔ Animated Live Indicators
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| PremiumTopBar(
|     username = "Administrator",
|     securityStatus = "Protected"
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   TOP BAR STATUS TYPES
   ========================================================= */

enum class TopBarSecurityState {

    SECURE,

    MONITORING,

    WARNING,

    CRITICAL
}



/* =========================================================
   STATUS STYLE MODEL
   ========================================================= */

data class TopBarStatusStyle(

    val color: Color,

    val label: String
)



/* =========================================================
   STATUS STYLE ENGINE
   ========================================================= */

object TopBarStatusEngine {

    fun style(
        state: TopBarSecurityState
    ): TopBarStatusStyle {

        return when (state) {

            TopBarSecurityState.SECURE ->
                TopBarStatusStyle(

                    color = Threat_Low,

                    label = "System Secure"
                )

            TopBarSecurityState.MONITORING ->
                TopBarStatusStyle(

                    color = AI_Active,

                    label = "AI Monitoring"
                )

            TopBarSecurityState.WARNING ->
                TopBarStatusStyle(

                    color = Threat_Medium,

                    label = "Security Warning"
                )

            TopBarSecurityState.CRITICAL ->
                TopBarStatusStyle(

                    color = Threat_Critical,

                    label = "Critical Threat"
                )
        }
    }
}



/* =========================================================
   MAIN PREMIUM TOP BAR
   ========================================================= */

@Composable
fun PremiumTopBar(

    modifier: Modifier = Modifier,

    username: String,

    securityState: TopBarSecurityState =
        TopBarSecurityState.SECURE,

    notificationCount: Int = 0,

    onMenuClick: () -> Unit = {},

    onSearchClick: () -> Unit = {},

    onNotificationClick: () -> Unit = {},

    onProfileClick: () -> Unit = {}
) {

    val statusStyle =
        TopBarStatusEngine.style(
            securityState
        )



    /*
    |--------------------------------------------------------------------------
    | LIVE PULSE ANIMATION
    |--------------------------------------------------------------------------
    */

    val infiniteTransition =
        rememberInfiniteTransition()

    val pulseAlpha by infiniteTransition.animateFloat(

        initialValue = 0.35f,

        targetValue = 1f,

        animationSpec = infiniteRepeatable(

            animation = tween(1000),

            repeatMode = RepeatMode.Reverse
        )
    )



    /*
    |--------------------------------------------------------------------------
    | STATUS COLOR ANIMATION
    |--------------------------------------------------------------------------
    */

    val animatedStatusColor by animateColorAsState(

        targetValue = statusStyle.color,

        animationSpec = tween(600)
    )



    /*
    |--------------------------------------------------------------------------
    | PROFILE MENU
    |--------------------------------------------------------------------------
    */

    var profileExpanded by remember {

        mutableStateOf(false)
    }



    /*
    |--------------------------------------------------------------------------
    | MAIN CONTAINER
    |--------------------------------------------------------------------------
    */

    Surface(

        modifier = modifier
            .fillMaxWidth()
            .shadow(

                elevation =
                    SentriXShadow.Medium,

                ambientColor =
                    animatedStatusColor.copy(
                        alpha = 0.18f
                    )
            ),

        color = Color.Transparent
    ) {

        Box(

            modifier = Modifier
                .fillMaxWidth()
                .background(

                    brush =
                        GlassGradients
                            .PremiumGlass
                )
                .blur(0.3.dp)
                .border(

                    width = 1.dp,

                    color =
                        Color.White.copy(
                            alpha = 0.08f
                        )
                )
                .padding(

                    horizontal =
                        SentriXSpacing.ExtraLarge,

                    vertical =
                        SentriXSpacing.Large
                )
        ) {

            Row(

                modifier = Modifier.fillMaxWidth(),

                horizontalArrangement =
                    Arrangement.SpaceBetween,

                verticalAlignment =
                    Alignment.CenterVertically
            ) {

                /*
                |--------------------------------------------------------------------------
                | LEFT SECTION
                |--------------------------------------------------------------------------
                */

                Row(

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    /*
                    |--------------------------------------------------------------------------
                    | MENU BUTTON
                    |--------------------------------------------------------------------------
                    */

                    IconButton(

                        onClick = onMenuClick
                    ) {

                        Box(

                            modifier = Modifier
                                .size(42.dp)
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
                                    Icons.Default.Menu,

                                contentDescription =
                                    "Menu",

                                tint =
                                    Text_Primary
                            )
                        }
                    }



                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Large
                        )
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | BRANDING SECTION
                    |--------------------------------------------------------------------------
                    */

                    Column {

                        Text(

                            text = "SentriX",

                            style =
                                HeadlineTypography.Small,

                            color =
                                Text_Primary,

                            fontWeight =
                                FontWeight.ExtraBold
                        )

                        Spacer(
                            modifier = Modifier.height(
                                2.dp
                            )
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
                                        animatedStatusColor
                                    )
                            )

                            Spacer(
                                modifier = Modifier.width(
                                    SentriXSpacing
                                        .Small
                                )
                            )

                            Text(

                                text =
                                    statusStyle.label,

                                style =
                                    TerminalTypography
                                        .Body,

                                color =
                                    animatedStatusColor
                            )
                        }
                    }
                }



                /*
                |--------------------------------------------------------------------------
                | RIGHT SECTION
                |--------------------------------------------------------------------------
                */

                Row(

                    verticalAlignment =
                        Alignment.CenterVertically
                ) {

                    /*
                    |--------------------------------------------------------------------------
                    | SEARCH BUTTON
                    |--------------------------------------------------------------------------
                    */

                    PremiumTopBarActionButton(

                        icon =
                            Icons.Default.Search,

                        onClick =
                            onSearchClick
                    )



                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | AI STATUS BUTTON
                    |--------------------------------------------------------------------------
                    */

                    Box {

                        PremiumTopBarActionButton(

                            icon =
                                Icons.Default.Memory,

                            glowColor =
                                AI_Active,

                            onClick = {}
                        )

                        Box(

                            modifier = Modifier
                                .align(
                                    Alignment.TopEnd
                                )
                                .padding(4.dp)
                                .size(10.dp)
                                .alpha(
                                    pulseAlpha
                                )
                                .clip(
                                    CircleShape
                                )
                                .background(
                                    AI_Active
                                )
                        )
                    }



                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Small
                        )
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | NOTIFICATION BUTTON
                    |--------------------------------------------------------------------------
                    */

                    BadgedBox(

                        badge = {

                            if (
                                notificationCount > 0
                            ) {

                                Badge(

                                    containerColor =
                                        Threat_Critical
                                ) {

                                    Text(
                                        text =
                                            notificationCount
                                                .toString()
                                    )
                                }
                            }
                        }
                    ) {

                        PremiumTopBarActionButton(

                            icon =
                                Icons.Default.Notifications,

                            glowColor =
                                Threat_Critical,

                            onClick =
                                onNotificationClick
                        )
                    }



                    Spacer(
                        modifier = Modifier.width(
                            SentriXSpacing.Large
                        )
                    )



                    /*
                    |--------------------------------------------------------------------------
                    | PROFILE SECTION
                    |--------------------------------------------------------------------------
                    */

                    Box {

                        Row(

                            modifier = Modifier
                                .clip(
                                    RoundedCornerShape(
                                        100.dp
                                    )
                                )
                                .background(

                                    color =
                                        Background_Secondary
                                )
                                .border(

                                    width = 1.dp,

                                    color =
                                        animatedStatusColor
                                            .copy(
                                                alpha = 0.25f
                                            ),

                                    shape =
                                        RoundedCornerShape(
                                            100.dp
                                        )
                                )
                                .padding(

                                    horizontal =
                                        SentriXSpacing
                                            .Medium,

                                    vertical =
                                        SentriXSpacing
                                            .Small
                                ),

                            verticalAlignment =
                                Alignment.CenterVertically
                        ) {

                            /*
                            |--------------------------------------------------------------------------
                            | PROFILE AVATAR
                            |--------------------------------------------------------------------------
                            */

                            Box(

                                modifier = Modifier
                                    .size(42.dp)
                                    .clip(
                                        CircleShape
                                    )
                                    .background(

                                        brush =
                                            BrandGradients
                                                .Primary
                                    ),

                                contentAlignment =
                                    Alignment.Center
                            ) {

                                Text(

                                    text =
                                        username
                                            .take(1),

                                    style =
                                        ButtonTypography
                                            .Large,

                                    color =
                                        Text_Primary
                                )
                            }



                            Spacer(
                                modifier = Modifier.width(
                                    SentriXSpacing
                                        .Medium
                                )
                            )



                            /*
                            |--------------------------------------------------------------------------
                            | PROFILE DETAILS
                            |--------------------------------------------------------------------------
                            */

                            Column {

                                Text(

                                    text = username,

                                    style =
                                        BodyTypography
                                            .Medium,

                                    color =
                                        Text_Primary
                                )

                                Text(

                                    text =
                                        "Administrator",

                                    style =
                                        BodyTypography
                                            .Tiny,

                                    color =
                                        Text_Secondary
                                )
                            }



                            Spacer(
                                modifier = Modifier.width(
                                    SentriXSpacing
                                        .Medium
                                )
                            )



                            /*
                            |--------------------------------------------------------------------------
                            | DROPDOWN BUTTON
                            |--------------------------------------------------------------------------
                            */

                            IconButton(

                                onClick = {

                                    profileExpanded =
                                        true

                                    onProfileClick()
                                }
                            ) {

                                Icon(

                                    imageVector =
                                        Icons.Default
                                            .KeyboardArrowDown,

                                    contentDescription =
                                        null,

                                    tint =
                                        Text_Primary
                                )
                            }
                        }



                        /*
                        |--------------------------------------------------------------------------
                        | PROFILE DROPDOWN MENU
                        |--------------------------------------------------------------------------
                        */

                        DropdownMenu(

                            expanded =
                                profileExpanded,

                            onDismissRequest = {

                                profileExpanded =
                                    false
                            }

                        ) {

                            DropdownMenuItem(

                                text = {

                                    Text(
                                        "Profile"
                                    )
                                },

                                onClick = {

                                    profileExpanded =
                                        false
                                }
                            )

                            DropdownMenuItem(

                                text = {

                                    Text(
                                        "Settings"
                                    )
                                },

                                onClick = {

                                    profileExpanded =
                                        false
                                }
                            )

                            HorizontalDivider()

                            DropdownMenuItem(

                                text = {

                                    Text(
                                        "Logout"
                                    )
                                },

                                onClick = {

                                    profileExpanded =
                                        false
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}



/* =========================================================
   TOP BAR ACTION BUTTON
   ========================================================= */

@Composable
fun PremiumTopBarActionButton(

    icon: androidx.compose.ui.graphics.vector.ImageVector,

    glowColor: Color =
        SentriX_AccentCyan,

    onClick: () -> Unit
) {

    IconButton(

        onClick = onClick
    ) {

        Box(

            modifier = Modifier
                .size(48.dp)
                .shadow(

                    elevation =
                        SentriXShadow.Small,

                    shape = CircleShape,

                    ambientColor =
                        glowColor.copy(
                            alpha = 0.18f
                        )
                )
                .clip(CircleShape)
                .background(

                    color =
                        Background_Secondary
                )
                .border(

                    width = 1.dp,

                    color =
                        glowColor.copy(
                            alpha = 0.18f
                        ),

                    shape = CircleShape
                ),

            contentAlignment =
                Alignment.Center
        ) {

            Icon(

                imageVector = icon,

                contentDescription = null,

                tint = glowColor
            )
        }
    }
}



/* =========================================================
   FUTURE TOP BAR EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Real-time attack notifications
| ✔ AI voice assistant integration
| ✔ Live threat ticker
| ✔ Dynamic weather overlays
| ✔ GPU holographic top bar
| ✔ Runtime workspace switching
| ✔ Multi-user collaboration
| ✔ Threat heatmap preview
| ✔ Cloud sync indicators
| ✔ Quantum dashboard controls
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX PREMIUM TOP BAR
|--------------------------------------------------------------------------
*/
