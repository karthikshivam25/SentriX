package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentrix.ui.animations.ShieldProtectionAnimation

@Composable
fun SecurityOverviewCard(
    modifier: Modifier = Modifier,
    securityScore: Int = 98,
    activeThreats: Int = 0,
    securedApps: Int = 148,
    vpnEnabled: Boolean = true,
    firewallEnabled: Boolean = true,
    realTimeProtection: Boolean = true
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "security_card_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.7f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2200,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    val cardGradient = Brush.verticalGradient(
        colors = listOf(
            Color(0xFF111827),
            Color(0xFF0B1220)
        )
    )

    val glowGradient = Brush.linearGradient(
        colors = listOf(
            Color(0xFF00D9FF).copy(alpha = glowAlpha),
            Color(0xFF0066FF).copy(alpha = glowAlpha * 0.5f)
        )
    )

    Box(
        modifier = modifier
    ) {

        // OUTER GLOW
        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(35.dp)
                .clip(RoundedCornerShape(32.dp))
                .background(glowGradient)
        )

        Card(
            modifier = Modifier
                .fillMaxWidth(),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color.Transparent
            )
        ) {

            Box(
                modifier = Modifier
                    .background(cardGradient)
                    .padding(24.dp)
            ) {

                Column(
                    verticalArrangement = Arrangement.spacedBy(24.dp)
                ) {

                    // ----------------------------------------
                    // HEADER
                    // ----------------------------------------

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = "Security",
                                tint = Color(0xFF00D9FF),
                                modifier = Modifier.size(30.dp)
                            )

                            Spacer(modifier = Modifier.width(12.dp))

                            Column {

                                Text(
                                    text = "Security Overview",
                                    color = Color.White,
                                    fontSize = 20.sp,
                                    fontWeight = FontWeight.Bold
                                )

                                Spacer(modifier = Modifier.height(4.dp))

                                Text(
                                    text = "Real-time protection active",
                                    color = Color(0xFF9CA3AF),
                                    fontSize = 13.sp
                                )
                            }
                        }

                        SecurityScoreBadge(
                            score = securityScore
                        )
                    }

                    // ----------------------------------------
                    // CENTER SHIELD
                    // ----------------------------------------

                    Box(
                        modifier = Modifier.fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {

                        ShieldProtectionAnimation(
                            modifier = Modifier.size(220.dp),
                            isProtected = activeThreats == 0
                        )
                    }

                    // ----------------------------------------
                    // STATS GRID
                    // ----------------------------------------

                    Column(
                        verticalArrangement = Arrangement.spacedBy(14.dp)
                    ) {

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {

                            SecurityStatItem(
                                title = "Threats",
                                value = activeThreats.toString(),
                                accentColor = if (activeThreats == 0) {
                                    Color(0xFF00E676)
                                } else {
                                    Color(0xFFFF5252)
                                },
                                modifier = Modifier.weight(1f)
                            )

                            SecurityStatItem(
                                title = "Protected Apps",
                                value = securedApps.toString(),
                                accentColor = Color(0xFF00D9FF),
                                modifier = Modifier.weight(1f)
                            )
                        }

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {

                            SecurityStatusChip(
                                title = "VPN",
                                enabled = vpnEnabled,
                                modifier = Modifier.weight(1f)
                            )

                            SecurityStatusChip(
                                title = "Firewall",
                                enabled = firewallEnabled,
                                modifier = Modifier.weight(1f)
                            )

                            SecurityStatusChip(
                                title = "Realtime",
                                enabled = realTimeProtection,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityScoreBadge(
    score: Int
) {

    val scoreColor = when {
        score >= 90 -> Color(0xFF00E676)
        score >= 70 -> Color(0xFFFFC107)
        else -> Color(0xFFFF5252)
    }

    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(18.dp))
            .background(
                scoreColor.copy(alpha = 0.15f)
            )
            .padding(
                horizontal = 16.dp,
                vertical = 10.dp
            ),
        contentAlignment = Alignment.Center
    ) {

        Text(
            text = "$score%",
            color = scoreColor,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun SecurityStatItem(
    title: String,
    value: String,
    accentColor: Color,
    modifier: Modifier = Modifier
) {

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .background(
                Color.White.copy(alpha = 0.04f)
            )
            .padding(18.dp)
    ) {

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = value,
            color = accentColor,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
private fun SecurityStatusChip(
    title: String,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {

    val statusColor = if (enabled) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    Box(
        modifier = modifier
            .clip(RoundedCornerShape(18.dp))
            .background(
                statusColor.copy(alpha = 0.12f)
            )
            .padding(vertical = 14.dp),
        contentAlignment = Alignment.Center
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(RoundedCornerShape(50))
                    .background(statusColor)
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = title,
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}
