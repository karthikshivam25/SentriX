package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PhoneAndroid
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
fun DeviceHealthCard(
    modifier: Modifier = Modifier,
    batteryLevel: Int = 86,
    ramUsage: Int = 58,
    storageUsage: Int = 71,
    deviceTemperature: String = "34°C"
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "device_health_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
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
                .blur(32.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF00E676).copy(alpha = glowAlpha),
                            Color(0xFF00D9FF).copy(alpha = glowAlpha * 0.5f)
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
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(54.dp)
                            .clip(CircleShape)
                            .background(
                                Color(0xFF00E676).copy(alpha = 0.12f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.PhoneAndroid,
                            contentDescription = "Device Health",
                            tint = Color(0xFF00E676),
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column {

                        Text(
                            text = "Device Health",
                            color = Color.White,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "System resources & performance",
                            color = Color(0xFF9CA3AF),
                            fontSize = 13.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // HEALTH METRICS
                // ----------------------------------------

                HealthProgressItem(
                    title = "Battery",
                    value = "$batteryLevel%",
                    progress = batteryLevel / 100f,
                    icon = Icons.Default.BatteryChargingFull,
                    accentColor = Color(0xFF00E676)
                )

                Spacer(modifier = Modifier.height(20.dp))

                HealthProgressItem(
                    title = "RAM Usage",
                    value = "$ramUsage%",
                    progress = ramUsage / 100f,
                    icon = Icons.Default.Memory,
                    accentColor = Color(0xFF00D9FF)
                )

                Spacer(modifier = Modifier.height(20.dp))

                HealthProgressItem(
                    title = "Storage",
                    value = "$storageUsage%",
                    progress = storageUsage / 100f,
                    icon = Icons.Default.Storage,
                    accentColor = Color(0xFFFFC107)
                )

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // TEMPERATURE STATUS
                // ----------------------------------------

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(22.dp))
                        .background(
                            Color.White.copy(alpha = 0.04f)
                        )
                        .padding(
                            horizontal = 18.dp,
                            vertical = 16.dp
                        ),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Column {

                        Text(
                            text = "Device Temperature",
                            color = Color(0xFF9CA3AF),
                            fontSize = 13.sp
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = deviceTemperature,
                            color = Color.White,
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(16.dp))
                            .background(
                                Color(0xFF00E676).copy(alpha = 0.14f)
                            )
                            .padding(
                                horizontal = 14.dp,
                                vertical = 10.dp
                            )
                    ) {

                        Text(
                            text = "NORMAL",
                            color = Color(0xFF00E676),
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HealthProgressItem(
    title: String,
    value: String,
    progress: Float,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    accentColor: Color
) {

    Column {

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = accentColor,
                    modifier = Modifier.size(22.dp)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Text(
                    text = title,
                    color = Color.White,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            Text(
                text = value,
                color = accentColor,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .height(10.dp)
                .clip(RoundedCornerShape(50)),
            color = accentColor,
            trackColor = Color.White.copy(alpha = 0.08f)
        )
    }
}
