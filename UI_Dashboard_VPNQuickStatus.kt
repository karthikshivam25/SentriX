package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Switch
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
import com.sentrix.ui.animations.VPNConnectAnimation

@Composable
fun VPNQuickStatus(
    modifier: Modifier = Modifier,
    isConnected: Boolean = true,
    serverLocation: String = "Singapore",
    ping: String = "18 ms",
    protocol: String = "WireGuard",
    onVpnToggle: (Boolean) -> Unit = {}
) {

    var vpnEnabled by remember {
        mutableStateOf(isConnected)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_status_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
        targetValue = 0.45f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2200,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    val primaryColor = if (vpnEnabled) {
        Color(0xFF00D9FF)
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
                .blur(34.dp)
                .clip(RoundedCornerShape(30.dp))
                .background(
                    Brush.linearGradient(
                        colors = listOf(
                            primaryColor.copy(alpha = glowAlpha),
                            primaryColor.copy(alpha = glowAlpha * 0.35f)
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
                                .size(56.dp)
                                .clip(CircleShape)
                                .background(
                                    primaryColor.copy(alpha = 0.14f)
                                ),
                            contentAlignment = Alignment.Center
                        ) {

                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = "VPN",
                                tint = primaryColor,
                                modifier = Modifier.size(30.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(16.dp))

                        Column {

                            Text(
                                text = "VPN Protection",
                                color = Color.White,
                                fontSize = 21.sp,
                                fontWeight = FontWeight.Bold
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = if (vpnEnabled) {
                                    "Encrypted secure connection"
                                } else {
                                    "VPN disconnected"
                                },
                                color = primaryColor,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }

                    Switch(
                        checked = vpnEnabled,
                        onCheckedChange = {
                            vpnEnabled = it
                            onVpnToggle.invoke(it)
                        }
                    )
                }

                Spacer(modifier = Modifier.height(26.dp))

                // ----------------------------------------
                // VPN ANIMATION
                // ----------------------------------------

                Box(
                    modifier = Modifier.fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {

                    VPNConnectAnimation(
                        modifier = Modifier.size(180.dp),
                        isConnected = vpnEnabled
                    )
                }

                Spacer(modifier = Modifier.height(26.dp))

                // ----------------------------------------
                // VPN DETAILS
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    VPNInfoItem(
                        modifier = Modifier.weight(1f),
                        title = "Location",
                        value = serverLocation,
                        icon = Icons.Default.Public,
                        accentColor = Color(0xFF00D9FF)
                    )

                    VPNInfoItem(
                        modifier = Modifier.weight(1f),
                        title = "Latency",
                        value = ping,
                        icon = Icons.Default.Speed,
                        accentColor = Color(0xFF00E676)
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // ----------------------------------------
                // PROTOCOL STATUS
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

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.Language,
                            contentDescription = "Protocol",
                            tint = primaryColor,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "Connection Protocol",
                                color = Color(0xFF9CA3AF),
                                fontSize = 12.sp
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = protocol,
                                color = Color.White,
                                fontSize = 15.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(16.dp))
                            .background(
                                primaryColor.copy(alpha = 0.14f)
                            )
                            .padding(
                                horizontal = 14.dp,
                                vertical = 8.dp
                            )
                    ) {

                        Text(
                            text = if (vpnEnabled) {
                                "SECURED"
                            } else {
                                "OFFLINE"
                            },
                            color = primaryColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun VPNInfoItem(
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

        Icon(
            imageVector = icon,
            contentDescription = title,
            tint = accentColor,
            modifier = Modifier.size(24.dp)
        )

        Spacer(modifier = Modifier.height(14.dp))

        Text(
            text = title,
            color = Color(0xFF9CA3AF),
            fontSize = 13.sp
        )

        Spacer(modifier = Modifier.height(6.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
