package com.sentrix.ui.vpn

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberInfiniteTransition
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class VPNMapData(
    val currentLocation: String,
    val connectedServer: String,
    val connectionStrength: Int,
    val isConnected: Boolean
)

@Composable
fun VPNMapView(

    data: VPNMapData,
    modifier: Modifier = Modifier
) {

    val statusColor = if (data.isConnected) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFF5252)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_map_animation"
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
        shape = RoundedCornerShape(28.dp),
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
                .padding(22.dp)
        ) {

            Column {

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.Public,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = "Global VPN Route",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(26.dp))

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(260.dp)
                        .clip(RoundedCornerShape(24.dp))
                        .background(Color(0xFF111827))
                ) {

                    Canvas(
                        modifier = Modifier.fillMaxSize()
                    ) {

                        val startPoint = Offset(
                            x = size.width * 0.25f,
                            y = size.height * 0.65f
                        )

                        val endPoint = Offset(
                            x = size.width * 0.72f,
                            y = size.height * 0.35f
                        )

                        drawCircle(
                            color = statusColor.copy(alpha = pulseAlpha),
                            radius = 34f,
                            center = startPoint
                        )

                        drawCircle(
                            color = statusColor,
                            radius = 14f,
                            center = startPoint
                        )

                        drawCircle(
                            color = Color(0xFF00E5FF).copy(alpha = pulseAlpha),
                            radius = 34f,
                            center = endPoint
                        )

                        drawCircle(
                            color = Color(0xFF00E5FF),
                            radius = 14f,
                            center = endPoint
                        )

                        drawLine(
                            brush = Brush.horizontalGradient(
                                colors = listOf(
                                    statusColor,
                                    Color(0xFF00E5FF)
                                )
                            ),
                            start = startPoint,
                            end = endPoint,
                            strokeWidth = 8f,
                            cap = StrokeCap.Round,
                            pathEffect = PathEffect.dashPathEffect(
                                floatArrayOf(20f, 14f),
                                0f
                            )
                        )
                    }

                    Column(
                        modifier = Modifier.fillMaxSize()
                    ) {

                        Spacer(modifier = Modifier.height(24.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {

                            VPNMapLocationCard(
                                modifier = Modifier.padding(start = 18.dp),
                                title = "Current",
                                location = data.currentLocation,
                                iconColor = statusColor
                            )

                            VPNMapLocationCard(
                                modifier = Modifier.padding(end = 18.dp),
                                title = "VPN Server",
                                location = data.connectedServer,
                                iconColor = Color(0xFF00E5FF)
                            )
                        }

                        Spacer(modifier = Modifier.weight(1f))

                        Surface(
                            modifier = Modifier
                                .align(Alignment.CenterHorizontally)
                                .padding(bottom = 18.dp),
                            shape = RoundedCornerShape(50),
                            color = Color(0x2215E676)
                        ) {

                            Row(
                                modifier = Modifier.padding(
                                    horizontal = 18.dp,
                                    vertical = 10.dp
                                ),
                                verticalAlignment = Alignment.CenterVertically
                            ) {

                                Icon(
                                    imageVector = Icons.Default.Security,
                                    contentDescription = null,
                                    tint = statusColor,
                                    modifier = Modifier.size(18.dp)
                                )

                                Spacer(modifier = Modifier.width(8.dp))

                                Text(
                                    text = "Connection Strength ${data.connectionStrength}%",
                                    color = Color.White,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun VPNMapLocationCard(

    modifier: Modifier = Modifier,
    title: String,
    location: String,
    iconColor: Color
) {

    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(18.dp),
        color = Color(0xCC0F172A)
    ) {

        Row(
            modifier = Modifier.padding(
                horizontal = 14.dp,
                vertical = 10.dp
            ),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(34.dp)
                    .clip(CircleShape)
                    .background(iconColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = Icons.Default.LocationOn,
                    contentDescription = null,
                    tint = iconColor,
                    modifier = Modifier.size(18.dp)
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            Column {

                Text(
                    text = title,
                    color = Color.Gray,
                    fontSize = 11.sp
                )

                Spacer(modifier = Modifier.height(2.dp))

                Text(
                    text = location,
                    color = Color.White,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
fun VPNMapPreviewData(): VPNMapData {

    return VPNMapData(
        currentLocation = "Chennai, India",
        connectedServer = "Singapore",
        connectionStrength = 96,
        isConnected = true
    )
}
