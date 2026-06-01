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
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Text
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
import androidx.compose.ui.unit.dp
import com.sentrix.ui.theme.*

/*
|--------------------------------------------------------------------------
| SENTRIX CYBER BOTTOM NAVIGATION
|--------------------------------------------------------------------------
|
| PURPOSE:
| Enterprise futuristic bottom navigation system for SentriX.
|
| FEATURES:
|
| ✔ Animated Navigation
| ✔ Neon Active Indicators
| ✔ Cyberpunk Glow Effects
| ✔ AI Monitoring Indicator
| ✔ Threat Alert Badges
| ✔ AMOLED Optimized
| ✔ Glassmorphism Compatible
| ✔ Responsive Layout
| ✔ Animated Selection Effects
| ✔ Enterprise Dashboard Navigation
|
|--------------------------------------------------------------------------
| USAGE
|--------------------------------------------------------------------------
|
| CyberBottomNav(
|     selectedItem = currentIndex,
|     onItemSelected = { }
| )
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   NAVIGATION DATA MODEL
   ========================================================= */

data class CyberNavItem(

    val title: String,

    val icon: ImageVector,

    val activeColor: Color,

    val notificationCount: Int = 0
)



/* =========================================================
   DEFAULT NAVIGATION ITEMS
   ========================================================= */

object CyberNavigationItems {

    val Dashboard = CyberNavItem(

        title = "Dashboard",

        icon = Icons.Default.Dashboard,

        activeColor = SentriX_AccentCyan
    )

    val Threats = CyberNavItem(

        title = "Threats",

        icon = Icons.Default.GppBad,

        activeColor = Threat_Critical,

        notificationCount = 3
    )

    val AI = CyberNavItem(

        title = "AI",

        icon = Icons.Default.Memory,

        activeColor = AI_Active
    )

    val Analytics = CyberNavItem(

        title = "Analytics",

        icon = Icons.Default.Analytics,

        activeColor = SentriX_AccentPurple
    )

    val Settings = CyberNavItem(

        title = "Settings",

        icon = Icons.Default.Settings,

        activeColor = SentriX_AccentTeal
    )

    val DefaultItems = listOf(

        Dashboard,

        Threats,

        AI,

        Analytics,

        Settings
    )
}



/* =========================================================
   MAIN CYBER BOTTOM NAVIGATION
   ========================================================= */

@Composable
fun CyberBottomNav(

    modifier: Modifier = Modifier,

    selectedItem: Int,

    items: List<CyberNavItem> =
        CyberNavigationItems.DefaultItems,

    onItemSelected: (Int) -> Unit
) {

    /*
    |--------------------------------------------------------------------------
    | LIVE PULSE ANIMATION
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
    | MAIN NAVIGATION BAR
    |--------------------------------------------------------------------------
    */

    NavigationBar(

        modifier = modifier
            .fillMaxWidth()
            .height(
                NavigationDimensions
                    .BottomBarHeight + 12.dp
            )
            .shadow(

                elevation =
                    SentriXShadow.Huge,

                ambientColor =
                    SentriX_AccentCyan.copy(
                        alpha = 0.12f
                    )
            )
            .background(

                brush =
                    GlassGradients
                        .PremiumGlass
            )
            .border(

                width = 1.dp,

                color =
                    Color.White.copy(
                        alpha = 0.06f
                    ),

                shape =
                    RoundedCornerShape(
                        topStart = 28.dp,
                        topEnd = 28.dp
                    )
            ),

        containerColor =
            Background_Main.copy(
                alpha = 0.92f
            ),

        tonalElevation = 0.dp
    ) {

        items.forEachIndexed {

                index,
                item ->

            val isSelected =
                selectedItem == index



            /*
            |--------------------------------------------------------------------------
            | ACTIVE COLOR ANIMATION
            |--------------------------------------------------------------------------
            */

            val animatedColor by animateColorAsState(

                targetValue = if (isSelected)
                    item.activeColor
                else
                    Text_Muted,

                animationSpec = tween(400)
            )



            /*
            |--------------------------------------------------------------------------
            | ICON FLOAT ANIMATION
            |--------------------------------------------------------------------------
            */

            val iconOffset by infiniteTransition
                .animateFloat(

                    initialValue = 0f,

                    targetValue = -4f,

                    animationSpec =
                        infiniteRepeatable(

                            animation = tween(
                                1200
                            ),

                            repeatMode =
                                RepeatMode.Reverse
                        )
                )



            /*
            |--------------------------------------------------------------------------
            | NAVIGATION ITEM
            |--------------------------------------------------------------------------
            */

            NavigationBarItem(

                selected = isSelected,

                onClick = {

                    onItemSelected(index)
                },

                colors =
                    NavigationBarItemDefaults
                        .colors(

                            selectedIconColor =
                                item.activeColor,

                            selectedTextColor =
                                item.activeColor,

                            unselectedIconColor =
                                Text_Muted,

                            unselectedTextColor =
                                Text_Muted,

                            indicatorColor =
                                Color.Transparent
                        ),

                icon = {

                    Box(

                        contentAlignment =
                            Alignment.Center
                    ) {

                        /*
                        |--------------------------------------------------------------------------
                        | ACTIVE GLOW BACKGROUND
                        |--------------------------------------------------------------------------
                        */

                        if (isSelected) {

                            Box(

                                modifier = Modifier
                                    .size(54.dp)
                                    .alpha(
                                        pulseAlpha
                                    )
                                    .clip(
                                        CircleShape
                                    )
                                    .background(

                                        brush =
                                            Brush.radialGradient(

                                                colors = listOf(

                                                    item.activeColor
                                                        .copy(
                                                            alpha = 0.28f
                                                        ),

                                                    Color.Transparent
                                                )
                                            )
                                    )
                            )
                        }



                        /*
                        |--------------------------------------------------------------------------
                        | ICON CONTAINER
                        |--------------------------------------------------------------------------
                        */

                        Box(

                            modifier = Modifier
                                .offset(

                                    y = if (isSelected)
                                        iconOffset.dp
                                    else
                                        0.dp
                                )
                                .size(48.dp)
                                .clip(
                                    CircleShape
                                )
                                .background(

                                    color =
                                        if (isSelected)

                                            item.activeColor.copy(
                                                alpha = 0.16f
                                            )

                                        else

                                            Color.Transparent
                                )
                                .border(

                                    width = if (isSelected)
                                        1.dp
                                    else
                                        0.dp,

                                    color =
                                        item.activeColor
                                            .copy(
                                                alpha = 0.45f
                                            ),

                                    shape =
                                        CircleShape
                                ),

                            contentAlignment =
                                Alignment.Center
                        ) {

                            Icon(

                                imageVector =
                                    item.icon,

                                contentDescription =
                                    item.title,

                                tint =
                                    animatedColor,

                                modifier = Modifier.size(
                                    IconDimensions
                                        .Medium
                                )
                            )
                        }



                        /*
                        |--------------------------------------------------------------------------
                        | NOTIFICATION BADGE
                        |--------------------------------------------------------------------------
                        */

                        if (
                            item.notificationCount > 0
                        ) {

                            Box(

                                modifier = Modifier
                                    .align(
                                        Alignment.TopEnd
                                    )
                                    .offset(
                                        x = 4.dp,
                                        y = (-2).dp
                                    )
                                    .size(18.dp)
                                    .clip(
                                        CircleShape
                                    )
                                    .background(
                                        Threat_Critical
                                    ),

                                contentAlignment =
                                    Alignment.Center
                            ) {

                                Text(

                                    text =
                                        item.notificationCount
                                            .toString(),

                                    style =
                                        BodyTypography
                                            .Tiny,

                                    color =
                                        Text_Primary,

                                    fontWeight =
                                        FontWeight.Bold
                                )
                            }
                        }
                    }
                },

                label = {

                    Text(

                        text = item.title,

                        style =
                            BodyTypography.Small,

                        color =
                            animatedColor,

                        fontWeight =
                            if (isSelected)

                                FontWeight.Bold

                            else

                                FontWeight.Medium
                    )
                }
            )
        }
    }
}



/* =========================================================
   MINI CYBER NAVIGATION
   ========================================================= */

@Composable
fun MiniCyberBottomNav(

    selectedItem: Int,

    onItemSelected: (Int) -> Unit
) {

    CyberBottomNav(

        selectedItem = selectedItem,

        items = listOf(

            CyberNavigationItems.Dashboard,

            CyberNavigationItems.Threats,

            CyberNavigationItems.Settings
        ),

        onItemSelected = onItemSelected
    )
}



/* =========================================================
   AI CYBER NAVIGATION
   ========================================================= */

@Composable
fun AICyberBottomNav(

    selectedItem: Int,

    onItemSelected: (Int) -> Unit
) {

    CyberBottomNav(

        selectedItem = selectedItem,

        items = listOf(

            CyberNavigationItems.Dashboard,

            CyberNavigationItems.AI,

            CyberNavigationItems.Analytics,

            CyberNavigationItems.Settings
        ),

        onItemSelected = onItemSelected
    )
}



/* =========================================================
   FUTURE CYBER NAVIGATION EXPANSION
   ========================================================= */

/*
|--------------------------------------------------------------------------
| FUTURE FEATURES
|--------------------------------------------------------------------------
|
| ✔ Holographic navigation system
| ✔ AI adaptive navigation
| ✔ Voice-controlled navigation
| ✔ Runtime navigation switching
| ✔ GPU neon rendering
| ✔ Dynamic cyber-grid overlays
| ✔ Gesture reactive controls
| ✔ Threat-aware navigation alerts
| ✔ Floating navigation mode
| ✔ VR/AR navigation rendering
|
|--------------------------------------------------------------------------
*/



/*
|--------------------------------------------------------------------------
| END OF SENTRIX CYBER BOTTOM NAVIGATION
|--------------------------------------------------------------------------
*/
