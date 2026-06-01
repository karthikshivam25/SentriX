package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryFull
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Storage
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
fun DeviceStatsCard(
    modifier: Modifier = Modifier,
    batteryLevel: Int = 82,
    ramUsage: Int = 64,
    storageUsage: Int = 71,
    networkStrength: Int = 92
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "device_stats_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.16f,
        targetValue = 0.42f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2400,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    Box(
        modifier = modifier
    ) {

        // ----------------------------------------
        // OUTER GLOW
        // ----------------------------------------

        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(34.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF00D9FF).copy(alpha = glowAlpha),
                            Color(0xFF00E676).copy(alpha = glowAlpha * 0.35f)
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

                Text(
                    text = "Device Statistics",
                    color = Color.White,
                    fontSize = 21.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = "Realtime hardware monitoring",
                    color = Color(0xFF9CA3AF),
                    fontSize = 13.sp
                )

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // STATS GRID
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    DeviceStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Battery",
                        value = "$batteryLevel%",
                        progress = batteryLevel / 100f,
                        icon = Icons.Default.BatteryFull,
                        accentColor = Color(0xFF00E676)
                    )

                    DeviceStatItem(
                        modifier = Modifier.weight(1f),
                        title = "RAM",
                        value = "$ramUsage%",
                        progress = ramUsage / 100f,
                        icon = Icons.Default.Memory,
                        accentColor = Color(0xFF00D9FF)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    DeviceStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Storage",
                        value = "$storageUsage%",
                        progress = storageUsage / 100f,
                        icon = Icons.Default.Storage,
                        accentColor = Color(0xFFFFC107)
                    )

                    DeviceStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Network",
                        value = "$networkStrength%",
                        progress = networkStrength / 100f,
                        icon = Icons.Default.NetworkCheck,
                        accentColor = Color(0xFF8B5CF6)
                    )
                }
            }
        }
    }
}

@Composable
private fun DeviceStatItem(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    progress: Float,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accentColor: Color
) {

    Column(
        modifier = modifier
            .clip(RoundedCornerShape(24.dp))
            .background(
                Color.White.copy(alpha = 0.04f)
            )
            .padding(18.dp)
    ) {

        Box(
            modifier = Modifier
                .size(48.dp)
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
                modifier = Modifier.size(26.dp)
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )

        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 24.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(14.dp))

        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp)
                .clip(RoundedCornerShape(50)),
            color = accentColor,
            trackColor = Color.White.copy(alpha = 0.08f)
        )
    }
}
