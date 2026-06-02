package com.sentrix.ui.vpn

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Security
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

enum class VPNStatus {
    CONNECTED,
    CONNECTING,
    DISCONNECTED
}

data class VPNStatusData(
    val status: VPNStatus,
    val serverLocation: String,
    val protocol: String,
    val connectionTime: String
)

@Composable
fun VPNStatusIndicator(

    data: VPNStatusData,
    modifier: Modifier = Modifier,
    onPowerClick: () -> Unit = {}
) {

    val statusColor = when (data.status) {
        VPNStatus.CONNECTED -> Color(0xFF00E676)
        VPNStatus.CONNECTING -> Color(0xFFFFC400)
        VPNStatus.DISCONNECTED -> Color(0xFFFF5252)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_status_animation"
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
                        onClick = onPowerClick,
                        modifier = Modifier.size(96.dp),
                        colors = IconButtonDefaults.filledIconButtonColors(
                            containerColor = statusColor
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.PowerSettingsNew,
                            contentDescription = null,
                            tint = Color.Black,
                            modifier = Modifier.size(42.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(20.dp))

                Text(
                    text = when (data.status) {
                        VPNStatus.CONNECTED -> "VPN Connected"
                        VPNStatus.CONNECTING -> "Connecting VPN"
                        VPNStatus.DISCONNECTED -> "VPN Disconnected"
                    },
                    color = Color.White,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(10.dp))

                StatusChip(
                    status = data.status,
                    statusColor = statusColor
                )

                Spacer(modifier = Modifier.height(24.dp))

                VPNStatusDetails(
                    data = data
                )

                Spacer(modifier = Modifier.height(22.dp))

                AnimatedVisibility(
                    visible = data.status == VPNStatus.CONNECTED
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
                                text = "Military-grade encryption is active.",
                                color = Color.LightGray,
                                fontSize = 13.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun StatusChip(

    status: VPNStatus,
    statusColor: Color
) {

    val icon = when (status) {
        VPNStatus.CONNECTED -> Icons.Default.CheckCircle
        VPNStatus.CONNECTING -> Icons.Default.PowerSettingsNew
        VPNStatus.DISCONNECTED -> Icons.Default.CloudOff
    }

    Surface(
        shape = RoundedCornerShape(50),
        color = statusColor.copy(alpha = 0.15f)
    ) {

        Row(
            modifier = Modifier.padding(
                horizontal = 16.dp,
                vertical = 8.dp
            ),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = statusColor,
                modifier = Modifier.size(16.dp)
            )

            Spacer(modifier = Modifier.width(8.dp))

            Text(
                text = when (status) {
                    VPNStatus.CONNECTED -> "SECURE CONNECTION"
                    VPNStatus.CONNECTING -> "CONNECTING"
                    VPNStatus.DISCONNECTED -> "UNPROTECTED"
                },
                color = statusColor,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
        }
    }
}

@Composable
fun VPNStatusDetails(

    data: VPNStatusData
) {

    Column(
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        VPNStatusRow(
            label = "Server",
            value = data.serverLocation
        )

        VPNStatusRow(
            label = "Protocol",
            value = data.protocol
        )

        VPNStatusRow(
            label = "Connected Time",
            value = data.connectionTime
        )
    }
}

@Composable
fun VPNStatusRow(

    label: String,
    value: String
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {

        Text(
            text = label,
            color = Color.Gray,
            fontSize = 13.sp
        )

        Text(
            text = value,
            color = Color.White,
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
fun VPNStatusPreviewData(): VPNStatusData {

    return VPNStatusData(
        status = VPNStatus.CONNECTED,
        serverLocation = "Singapore • Ultra Node",
        protocol = "WireGuard",
        connectionTime = "01:42:18"
    )
}
