package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Psychology
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
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

@Composable
fun AIProtectionCard(
    modifier: Modifier = Modifier,
    aiProtectionEnabled: Boolean = true,
    aiDetectionRate: Int = 98,
    analyzedThreats: Int = 4821,
    suspiciousActivities: Int = 3,
    predictionAccuracy: Float = 0.98f
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "ai_protection_animation"
    )

    // GLOW PULSE
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
        targetValue = 0.48f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2200,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    // AI SCAN PULSE
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.95f,
        targetValue = 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1800,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_scale"
    )

    val primaryColor = if (aiProtectionEnabled) {
        Color(0xFF8B5CF6)
    } else {
        Color(0xFFFF5252)
    }

    Box(
        modifier = modifier
    ) {

        // ----------------------------------------
        // OUTER AI GLOW
        // ----------------------------------------

        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(36.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            primaryColor.copy(alpha = glowAlpha),
                            Color(0xFF00D9FF).copy(alpha = glowAlpha * 0.35f)
                        )
                    )
                )
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(30.dp),
            colors = CardDefaults.cardColors(
                containerColor = Color(0xFF111827)
            )
        ) {

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(22.dp)
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

                        Box(
                            modifier = Modifier
                                .size(58.dp)
                                .clip(CircleShape)
                                .background(
                                    primaryColor.copy(alpha = 0.14f)
                                ),
                            contentAlignment = Alignment.Center
                        ) {

                            Icon(
                                imageVector = Icons.Default.Psychology,
                                contentDescription = "AI Protection",
                                tint = primaryColor,
                                modifier = Modifier.size(32.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(16.dp))

                        Column {

                            Text(
                                text = "AI Protection Engine",
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = if (aiProtectionEnabled) {
                                    "Machine learning defense active"
                                } else {
                                    "AI protection disabled"
                                },
                                color = Color(0xFF9CA3AF),
                                fontSize = 13.sp
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(18.dp))
                            .background(
                                primaryColor.copy(alpha = 0.14f)
                            )
                            .padding(
                                horizontal = 14.dp,
                                vertical = 8.dp
                            )
                    ) {

                        Text(
                            text = "AI ACTIVE",
                            color = primaryColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                // ----------------------------------------
                // AI CORE STATUS
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(26.dp))
                        .background(
                            Color.White.copy(alpha = 0.04f)
                        )
                        .padding(22.dp)
                ) {

                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {

                        Box(
                            modifier = Modifier
                                .size(90.dp)
                                .clip(CircleShape)
                                .background(
                                    primaryColor.copy(alpha = 0.12f)
                                ),
                            contentAlignment = Alignment.Center
                        ) {

                            Icon(
                                imageVector = Icons.Default.AutoAwesome,
                                contentDescription = "AI Core",
                                tint = primaryColor,
                                modifier = Modifier
                                    .size(44.dp)
                            )
                        }

                        Spacer(modifier = Modifier.height(20.dp))

                        Text(
                            text = "$aiDetectionRate%",
                            color = primaryColor,
                            fontSize = 42.sp,
                            fontWeight = FontWeight.ExtraBold
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = "Threat Detection Accuracy",
                            color = Color(0xFF9CA3AF),
                            fontSize = 13.sp
                        )

                        Spacer(modifier = Modifier.height(20.dp))

                        LinearProgressIndicator(
                            progress = { predictionAccuracy },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(10.dp)
                                .clip(RoundedCornerShape(50)),
                            color = primaryColor,
                            trackColor = Color.White.copy(alpha = 0.08f)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // AI STATS GRID
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    AIStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Analyzed",
                        value = analyzedThreats.toString(),
                        icon = Icons.Default.Shield,
                        accentColor = Color(0xFF00D9FF)
                    )

                    AIStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Suspicious",
                        value = suspiciousActivities.toString(),
                        icon = Icons.Default.WarningAmber,
                        accentColor = Color(0xFFFF9100)
                    )
                }
            }
        }
    }
}

@Composable
private fun AIStatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accentColor: Color
) {

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(22.dp))
            .background(
                Color.White.copy(alpha = 0.04f)
            )
            .padding(18.dp)
    ) {

        Box(
            modifier = Modifier
                .size(46.dp)
                .clip(CircleShape)
                .background(
                    accentColor.copy(alpha = 0.14f)
                ),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = title,
                tint = accentColor,
                modifier = Modifier.size(24.dp)
            )
        }

        Spacer(modifier = Modifier.height(14.dp))

        Text(
            text = value,
            color = accentColor,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )
    }
}
