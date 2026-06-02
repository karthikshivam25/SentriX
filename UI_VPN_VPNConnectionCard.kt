package com.sentrix.ui.vpn

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberInfiniteTransition
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class VPNConnectionState {
    CONNECTED,
    CONNECTING,
    DISCONNECTED
}

data class VPNConnectionData(
    val state: VPNConnectionState,
    val serverName: String,
    val ipAddress: String,
    val encryption: String,
    val connectionDuration: String
)

@Composable
fun VPNConnectionCard(

    data: VPNConnectionData,
    modifier: Modifier = Modifier,
    onToggleConnection: () -> Unit = {}
) {

    val statusColor = when (data.state) {
        VPNConnectionState.CONNECTED -> Color(0xFF00E676)
        VPNConnectionState.CONNECTING -> Color(0xFFFFC400)
        VPNConnectionState.DISCONNECTED -> Color(0xFFFF5252)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_connection_animation"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1200,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(30.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 6.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1A1F35),
                            Color(0xFF101728)
                        )
                    )
                )
                .padding(24.dp)
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {

                Box(
                    modifier = Modifier.size(170.dp),
                    contentAlignment = Alignment.Center
                ) {

                    Box(
                        modifier = Modifier
                            .size(150.dp)
                            .clip(CircleShape)
                            .background(
                                statusColor.copy(alpha = 0.12f)
                            )
                            .alpha(pulseAlpha)
                    )

                    FilledIconButton(
                        onClick = onToggleConnection,
                        modifier = Modifier.size(92.dp),
                        colors = IconButtonDefaults.filledIconButtonColors(
                            containerColor = statusColor
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = null,
                            tint = Color.Black,
                            modifier = Modifier.size(38.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                Text(
                    text = when (data.state) {
                        VPNConnectionState.CONNECTED -> "VPN Connected"
                        VPNConnectionState.CONNECTING -> "Connecting Securely"
                        VPNConnectionState.DISCONNECTED -> "VPN Disconnected"
                    },
                    color = Color.White,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(statusColor)
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = data.serverName,
                        color = Color.LightGray,
                        fontSize = 14.sp
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                VPNConnectionInfoSection(
                    data = data,
                    statusColor = statusColor
                )

                Spacer(modifier = Modifier.height(20.dp))

                AnimatedVisibility(
                    visible = data.state == VPNConnectionState.CONNECTED
                ) {

                    Surface(
                        shape = RoundedCornerShape(18.dp),
                        color = Color(0xFF111827)
                    ) {

                        Row(
                            modifier = Modifier.padding(
                                horizontal = 18.dp,
                                vertical = 14.dp
                            ),
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                tint = Color(0xFF00E5FF)
                            )

                            Spacer(modifier = Modifier.width(10.dp))

                            Text(
                                text = "Your internet activity is encrypted and protected.",
                                color = Color.LightGray,
                                fontSize = 13.sp,
                                lineHeight = 20.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun VPNConnectionInfoSection(

    data: VPNConnectionData,
    statusColor: Color
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        VPNInfoRow(
            icon = Icons.Default.Public,
            label = "IP Address",
            value = data.ipAddress
        )

        VPNInfoRow(
            icon = Icons.Default.Security,
            label = "Encryption",
            value = data.encryption
        )

        VPNInfoRow(
            icon = Icons.Default.CheckCircle,
            label = "Connection Time",
            value = data.connectionDuration
        )

        Surface(
            shape = RoundedCornerShape(50),
            color = statusColor.copy(alpha = 0.15f)
        ) {

            Row(
                modifier = Modifier.padding(
                    horizontal = 14.dp,
                    vertical = 8.dp
                ),
                verticalAlignment = Alignment.CenterVertically
            ) {

                Icon(
                    imageVector = when (data.state) {
                        VPNConnectionState.CONNECTED -> Icons.Default.CheckCircle
                        VPNConnectionState.CONNECTING -> Icons.Default.WarningAmber
                        VPNConnectionState.DISCONNECTED -> Icons.Default.WarningAmber
                    },
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(15.dp)
                )

                Spacer(modifier = Modifier.width(8.dp))

                Text(
                    text = when (data.state) {
                        VPNConnectionState.CONNECTED -> "SECURE CONNECTION"
                        VPNConnectionState.CONNECTING -> "CONNECTING"
                        VPNConnectionState.DISCONNECTED -> "UNPROTECTED"
                    },
                    color = statusColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
fun VPNInfoRow(

    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    value: String
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(Color(0xFF1E293B)),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color(0xFF00E5FF),
                modifier = Modifier.size(20.dp)
            )
        }

        Spacer(modifier = Modifier.width(14.dp))

        Column(
            modifier = Modifier.weight(1f)
        ) {

            Text(
                text = label,
                color = Color.Gray,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(2.dp))

            Text(
                text = value,
                color = Color.White,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

@Composable
fun VPNConnectionPreviewData(): VPNConnectionData {

    return VPNConnectionData(
        state = VPNConnectionState.CONNECTED,
        serverName = "Singapore • Ultra Secure Node",
        ipAddress = "185.234.21.84",
        encryption = "AES-256 Encryption",
        connectionDuration = "01:42:18"
    )
}
