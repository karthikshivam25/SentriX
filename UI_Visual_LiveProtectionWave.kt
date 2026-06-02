package com.sentrix.ui.visual

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun LiveProtectionWaveCard() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(24.dp)
            )
            .padding(20.dp)
    ) {

        Column {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Live Protection",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Real-time system monitoring active",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            LiveWaveAnimation()

            Spacer(modifier = Modifier.height(24.dp))

            ProtectionStatusRow()
        }
    }
}

@Composable
fun LiveWaveAnimation() {

    val infiniteTransition = rememberInfiniteTransition(label = "wave_animation")

    val animatedOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1000f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 3500,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "wave_offset"
    )

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(180.dp)
    ) {

        val path = Path()

        val centerY = size.height / 2

        path.moveTo(0f, centerY)

        var x = 0f

        while (x < size.width) {

            val wave =
                kotlin.math.sin((x + animatedOffset) * 0.02f).toFloat()

            val y = centerY + (wave * 40f)

            path.lineTo(x, y)

            x += 8f
        }

        drawPath(
            path = path,
            brush = Brush.horizontalGradient(
                colors = listOf(
                    Color(0xFF2563EB),
                    Color(0xFF38BDF8),
                    Color(0xFF22C55E)
                )
            ),
            style = Stroke(
                width = 8f,
                cap = StrokeCap.Round
            )
        )

        drawCircle(
            color = Color(0xFF38BDF8),
            radius = 12f,
            center = Offset(size.width - 20f, centerY)
        )
    }
}

@Composable
fun ProtectionStatusRow() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        ProtectionStatusCard(
            title = "Threats",
            value = "0",
            accentColor = Color(0xFF22C55E)
        )

        ProtectionStatusCard(
            title = "Scans",
            value = "128",
            accentColor = Color(0xFF38BDF8)
        )

        ProtectionStatusCard(
            title = "Blocked",
            value = "24",
            accentColor = Color(0xFFFACC15)
        )
    }
}

@Composable
fun ProtectionStatusCard(
    title: String,
    value: String,
    accentColor: Color
) {

    Box(
        modifier = Modifier
            .background(
                color = Color(0xFF111827),
                shape = RoundedCornerShape(18.dp)
            )
            .padding(
                horizontal = 20.dp,
                vertical = 16.dp
            )
    ) {

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = value,
                color = accentColor,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = title,
                color = Color(0xFF94A3B8),
                fontSize = 13.sp
            )
        }
    }
}
