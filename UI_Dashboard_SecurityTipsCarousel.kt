package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class SecurityTip(
    val id: Int,
    val title: String,
    val description: String,
    val icon: ImageVector,
    val accentColor: Color
)

@Composable
fun SecurityTipsCarousel(
    modifier: Modifier = Modifier,
    tips: List<SecurityTip> = defaultSecurityTips()
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "security_tips_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.16f,
        targetValue = 0.42f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2500,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    Column(
        modifier = modifier.fillMaxWidth()
    ) {

        // ----------------------------------------
        // HEADER
        // ----------------------------------------

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {

            Column {

                Text(
                    text = "Security Tips",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = "Smart recommendations for stronger protection",
                    color = Color(0xFF9CA3AF),
                    fontSize = 13.sp
                )
            }

            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .background(
                        Color(0xFF00D9FF).copy(alpha = 0.14f)
                    )
                    .padding(
                        horizontal = 14.dp,
                        vertical = 8.dp
                    )
            ) {

                Text(
                    text = "${tips.size} Tips",
                    color = Color(0xFF00D9FF),
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(22.dp))

        // ----------------------------------------
        // TIPS CAROUSEL
        // ----------------------------------------

        LazyRow(
            horizontalArrangement = Arrangement.spacedBy(18.dp),
            contentPadding = PaddingValues(end = 12.dp)
        ) {

            items(tips) { tip ->

                SecurityTipCard(
                    tip = tip,
                    glowAlpha = glowAlpha
                )
            }
        }
    }
}

@Composable
private fun SecurityTipCard(
    tip: SecurityTip,
    glowAlpha: Float
) {

    Box {

        // ----------------------------------------
        // GLOW EFFECT
        // ----------------------------------------

        Box(
            modifier = Modifier
                .width(280.dp)
                .height(220.dp)
                .blur(34.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            tip.accentColor.copy(alpha = glowAlpha),
                            tip.accentColor.copy(alpha = glowAlpha * 0.3f)
                        )
                    )
                )
        )

        Card(
            modifier = Modifier
                .width(280.dp)
                .height(220.dp),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF111827)
            )
        ) {

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(22.dp)
            ) {

                // ----------------------------------------
                // ICON
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .size(60.dp)
                        .clip(CircleShape)
                        .background(
                            tip.accentColor.copy(alpha = 0.14f)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = tip.icon,
                        contentDescription = tip.title,
                        tint = tip.accentColor,
                        modifier = Modifier.size(32.dp)
                    )
                }

                Spacer(modifier = Modifier.height(22.dp))

                // ----------------------------------------
                // TEXT CONTENT
                // ----------------------------------------

                Text(
                    text = tip.title,
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    lineHeight = 26.sp
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = tip.description,
                    color = Color(0xFF9CA3AF),
                    fontSize = 14.sp,
                    lineHeight = 22.sp
                )

                Spacer(modifier = Modifier.weight(1f))

                // ----------------------------------------
                // STATUS BADGE
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(16.dp))
                        .background(
                            tip.accentColor.copy(alpha = 0.14f)
                        )
                        .padding(
                            horizontal = 14.dp,
                            vertical = 8.dp
                        )
                ) {

                    Text(
                        text = "RECOMMENDED",
                        color = tip.accentColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

private fun defaultSecurityTips(): List<SecurityTip> {

    return listOf(

        SecurityTip(
            id = 1,
            title = "Enable Multi-Factor Authentication",
            description = "Protect your accounts with an additional verification layer for enhanced security.",
            icon = Icons.Default.VerifiedUser,
            accentColor = Color(0xFF00E676)
        ),

        SecurityTip(
            id = 2,
            title = "Use Secure VPN Connection",
            description = "Encrypt your internet traffic to stay protected on public Wi-Fi networks.",
            icon = Icons.Default.Security,
            accentColor = Color(0xFF00D9FF)
        ),

        SecurityTip(
            id = 3,
            title = "Update Device Regularly",
            description = "Install the latest security patches and updates to prevent vulnerabilities.",
            icon = Icons.Default.SystemUpdateAlt,
            accentColor = Color(0xFFFFC107)
        ),

        SecurityTip(
            id = 4,
            title = "Monitor Suspicious Activity",
            description = "Review realtime logs and alerts to identify potential threats instantly.",
            icon = Icons.Default.Visibility,
            accentColor = Color(0xFFFF5252)
        )
    )
}
