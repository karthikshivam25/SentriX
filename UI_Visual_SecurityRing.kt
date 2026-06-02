package com.sentrix.ui.visual

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.foundation.Canvas
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun SecurityRingCard() {

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(24.dp)
            )
    ) {

        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "Security Score",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp
            )

            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "Real-time device protection status",
                color = Color(0xFF94A3B8),
                fontSize = 14.sp
            )

            Spacer(modifier = Modifier.height(28.dp))

            SecurityRingProgress(
                progress = 0.92f,
                score = 92
            )

            Spacer(modifier = Modifier.height(28.dp))

            SecurityStatusSection()

            Spacer(modifier = Modifier.height(24.dp))
        }
    }
}

@Composable
fun SecurityRingProgress(
    progress: Float,
    score: Int
) {

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier.size(240.dp)
    ) {

        Canvas(
            modifier = Modifier.size(240.dp)
        ) {

            val strokeWidth = 24f

            drawArc(
                color = Color(0xFF1E293B),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height),
                topLeft = Offset.Zero
            )

            drawArc(
                brush = Brush.sweepGradient(
                    colors = listOf(
                        Color(0xFF2563EB),
                        Color(0xFF38BDF8),
                        Color(0xFF22C55E),
                        Color(0xFF2563EB)
                    )
                ),
                startAngle = -90f,
                sweepAngle = 360f * progress,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height),
                topLeft = Offset.Zero
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "$score%",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 42.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "Protected",
                color = Color(0xFF94A3B8),
                fontSize = 14.sp
            )
        }
    }
}

@Composable
fun SecurityStatusSection() {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {

        SecurityStatusItem(
            title = "Firewall",
            status = "Active",
            statusColor = Color(0xFF22C55E)
        )

        SecurityStatusItem(
            title = "Threat Scanner",
            status = "Secured",
            statusColor = Color(0xFF38BDF8)
        )

        SecurityStatusItem(
            title = "Privacy Shield",
            status = "Protected",
            statusColor = Color(0xFFFACC15)
        )
    }
}

@Composable
fun SecurityStatusItem(
    title: String,
    status: String,
    statusColor: Color
) {

    Box(
        modifier = Modifier
            .fillMaxWidth(0.82f)
            .background(
                color = Color(0xFF111827),
                shape = RoundedCornerShape(16.dp)
            )
    ) {

        androidx.compose.foundation.layout.Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(58.dp)
                .background(
                    color = Color.Transparent,
                    shape = RoundedCornerShape(16.dp)
                ),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {

            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Medium,
                fontSize = 15.sp,
                modifier = Modifier.padding(start = 18.dp)
            )

            Box(
                modifier = Modifier
                    .padding(end = 16.dp)
                    .background(
                        color = statusColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(50)
                    )
            ) {

                Text(
                    text = status,
                    color = statusColor,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(
                        horizontal = 14.dp,
                        vertical = 6.dp
                    )
                )
            }
        }
    }
}
