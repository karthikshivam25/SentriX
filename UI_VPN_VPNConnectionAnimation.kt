package com.sentrix.ui.vpn

import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.cos
import kotlin.math.sin

enum class VPNAnimationState {
    CONNECTED,
    CONNECTING,
    DISCONNECTED
}

@Composable
fun VPNConnectionAnimation(

    state: VPNAnimationState,
    modifier: Modifier = Modifier
) {

    val statusColor = when (state) {
        VPNAnimationState.CONNECTED -> Color(0xFF00E676)
        VPNAnimationState.CONNECTING -> Color(0xFFFFC400)
        VPNAnimationState.DISCONNECTED -> Color(0xFFFF5252)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "vpn_connection_animation"
    )

    val rotationAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 4000,
                easing = LinearEasing
            )
        ),
        label = "rotation_animation"
    )

    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.85f,
        targetValue = 1.15f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1400,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_scale"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.25f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1400,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(32.dp),
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
                .padding(vertical = 36.dp),
            contentAlignment = Alignment.Center
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                Box(
                    modifier = Modifier.size(260.dp),
                    contentAlignment = Alignment.Center
                ) {

                    Box(
                        modifier = Modifier
                            .size((180 * pulseScale).dp)
                            .clip(CircleShape)
                            .background(
                                statusColor.copy(alpha = pulseAlpha * 0.18f)
                            )
                    )

                    Canvas(
                        modifier = Modifier.size(230.dp)
                    ) {

                        drawArc(
                            color = Color(0xFF2A3550),
                            startAngle = 0f,
                            sweepAngle = 360f,
                            useCenter = false,
                            style = Stroke(
                                width = 10.dp.toPx(),
                                cap = StrokeCap.Round
                            )
                        )

                        drawArc(
                            brush = Brush.sweepGradient(
                                colors = listOf(
                                    statusColor,
                                    Color(0xFF00E5FF),
                                    statusColor
                                )
                            ),
                            startAngle = rotationAngle,
                            sweepAngle = 110f,
                            useCenter = false,
                            style = Stroke(
                                width = 10.dp.toPx(),
                                cap = StrokeCap.Round
                            )
                        )

                        repeat(8) { index ->

                            val angle = Math.toRadians(
                                (rotationAngle + index * 45).toDouble()
                            )

                            val radius = size.minDimension / 2.2f

                            val x = center.x + radius * cos(angle).toFloat()
                            val y = center.y + radius * sin(angle).toFloat()

                            drawCircle(
                                color = statusColor.copy(alpha = 0.35f),
                                radius = 6.dp.toPx(),
                                center = Offset(x, y)
                            )
                        }
                    }

                    Box(
                        modifier = Modifier
                            .size(110.dp)
                            .clip(CircleShape)
                            .background(
                                brush = Brush.radialGradient(
                                    colors = listOf(
                                        statusColor.copy(alpha = 0.35f),
                                        Color(0xFF111827)
                                    )
                                )
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = when (state) {
                                VPNAnimationState.CONNECTED -> Icons.Default.Security
                                VPNAnimationState.CONNECTING -> Icons.Default.PowerSettingsNew
                                VPNAnimationState.DISCONNECTED -> Icons.Default.Lock
                            },
                            contentDescription = null,
                            tint = statusColor,
                            modifier = Modifier.size(50.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                Text(
                    text = when (state) {
                        VPNAnimationState.CONNECTED -> "Secure VPN Connected"
                        VPNAnimationState.CONNECTING -> "Establishing Secure Tunnel"
                        VPNAnimationState.DISCONNECTED -> "VPN Protection Disabled"
                    },
                    color = Color.White,
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = when (state) {
                        VPNAnimationState.CONNECTED ->
                            "Your internet traffic is encrypted and protected."

                        VPNAnimationState.CONNECTING ->
                            "Creating a private encrypted connection..."

                        VPNAnimationState.DISCONNECTED ->
                            "Your connection is currently unprotected."
                    },
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp,
                    modifier = Modifier.padding(horizontal = 32.dp)
                )

                Spacer(modifier = Modifier.height(24.dp))

                Surface(
                    shape = RoundedCornerShape(50),
                    color = statusColor.copy(alpha = 0.15f)
                ) {

                    Text(
                        text = when (state) {
                            VPNAnimationState.CONNECTED -> "SECURE"
                            VPNAnimationState.CONNECTING -> "CONNECTING"
                            VPNAnimationState.DISCONNECTED -> "UNPROTECTED"
                        },
                        modifier = Modifier.padding(
                            horizontal = 22.dp,
                            vertical = 10.dp
                        ),
                        color = statusColor,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                }
            }
        }
    }
}
