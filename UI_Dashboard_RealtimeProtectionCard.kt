package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.blur
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun RealtimeProtectionCard(
    modifier: Modifier = Modifier,
    protectionEnabled: Boolean = true,
    scannedFiles: Int = 12458,
    blockedThreats: Int = 37,
    lastScanTime: String = "2 mins ago",
    onToggleProtection: (Boolean) -> Unit = {}
) {

    var isEnabled by remember {
        mutableStateOf(protectionEnabled)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "realtime_protection_animation"
    )

    // GLOW ANIMATION
    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.5f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1800,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    // ROTATION ANIMATION
    val rotation by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 5000,
                easing = LinearEasing
            )
        ),
        label = "rotation"
    )

    val primaryColor = if (isEnabled) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    Box(
        modifier = modifier
    ) {

        // ----------------------------------------
        // OUTER GLOW
        // ----------------------------------------

        Box(
            modifier = Modifier
                .matchParentSize()
                .blur(35.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            primaryColor.copy(alpha = glowAlpha),
                            primaryColor.copy(alpha = glowAlpha * 0.3f)
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
                                    primaryColor.copy(alpha = 0.12f)
                                ),
                            contentAlignment = Alignment.Center
                        ) {

                            Icon(
                                imageVector = Icons.Default.GppGood,
                                contentDescription = "Protection",
                                tint = primaryColor,
                                modifier = Modifier.size(32.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(16.dp))

                        Column {

                            Text(
                                text = "Realtime Protection",
                                color = Color.White,
                                fontSize = 20.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = if (isEnabled) {
                                    "Actively monitoring threats"
                                } else {
                                    "Protection disabled"
                                },
                                color = Color(0xFF9CA3AF),
                                fontSize = 13.sp
                            )
                        }
                    }

                    Switch(
                        checked = isEnabled,
                        onCheckedChange = {
                            isEnabled = it
                            onToggleProtection.invoke(it)
                        },
                        thumbContent = {

                            Icon(
                                imageVector = Icons.Default.PowerSettingsNew,
                                contentDescription = null,
                                modifier = Modifier.size(14.dp)
                            )
                        }
                    )
                }

                Spacer(modifier = Modifier.height(28.dp))

                // ----------------------------------------
                // LIVE STATUS
                // ----------------------------------------

                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(24.dp))
                        .background(
                            Color.White.copy(alpha = 0.04f)
                        )
                        .padding(18.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.Sync,
                        contentDescription = "Live Scan",
                        tint = primaryColor,
                        modifier = Modifier
                            .size(28.dp)
                            .graphicsLayer {
                                rotationZ = rotation
                            }
                    )

                    Spacer(modifier = Modifier.width(14.dp))

                    Column {

                        Text(
                            text = if (isEnabled) {
                                "Live scanning active"
                            } else {
                                "Live scanning paused"
                            },
                            color = Color.White,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "Last update: $lastScanTime",
                            color = Color(0xFF9CA3AF),
                            fontSize = 12.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // STATS
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    ProtectionStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Scanned Files",
                        value = scannedFiles.toString(),
                        accentColor = Color(0xFF00D9FF)
                    )

                    ProtectionStatCard(
                        modifier = Modifier.weight(1f),
                        title = "Blocked Threats",
                        value = blockedThreats.toString(),
                        accentColor = primaryColor
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // STATUS BADGE
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(18.dp))
                        .background(
                            primaryColor.copy(alpha = 0.12f)
                        )
                        .padding(
                            horizontal = 16.dp,
                            vertical = 10.dp
                        )
                ) {

                    Text(
                        text = if (isEnabled) {
                            "SYSTEM SECURED"
                        } else {
                            "PROTECTION OFFLINE"
                        },
                        color = primaryColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun ProtectionStatCard(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
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

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = value,
            color = accentColor,
            fontSize = 26.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
