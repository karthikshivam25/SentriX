package com.sentrix.ui.scanner

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Autorenew
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class RealtimeScannerModel(
    val scannerStatus: String,
    val activeProcesses: Int,
    val scannedFiles: Int,
    val blockedThreats: Int,
    val cpuUsage: String,
    val memoryUsage: String,
    val realtimeMessage: String
)

@Composable
fun RealtimeScannerView(
    scanner: RealtimeScannerModel,
    modifier: Modifier = Modifier
) {

    val infiniteTransition = rememberInfiniteTransition(label = "scanner_animation")

    val rotationAnimation = infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2400,
                easing = LinearEasing
            ),
            repeatMode = RepeatMode.Restart
        ),
        label = "rotation"
    )

    val pulseAnimation = infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    val statusColor = when (scanner.scannerStatus) {
        "Protected" -> Color(0xFF00E676)
        "Scanning" -> Color(0xFF00BCD4)
        "Threat Detected" -> Color(0xFFFF5252)
        else -> Color(0xFFFFC400)
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 12.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF0F172A),
                            Color(0xFF172554),
                            Color(0xFF111827)
                        )
                    )
                )
                .padding(24.dp)
        ) {

            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                // Animated Scanner Icon
                Box(
                    contentAlignment = Alignment.Center
                ) {

                    Box(
                        modifier = Modifier
                            .size(110.dp)
                            .alpha(pulseAnimation.value)
                            .clip(CircleShape)
                            .background(statusColor.copy(alpha = 0.12f))
                    )

                    Box(
                        modifier = Modifier
                            .size(84.dp)
                            .clip(CircleShape)
                            .background(statusColor.copy(alpha = 0.18f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Autorenew,
                            contentDescription = null,
                            tint = statusColor,
                            modifier = Modifier
                                .size(42.dp)
                                .graphicsLayer {
                                    rotationZ = rotationAnimation.value
                                }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(22.dp))

                Text(
                    text = "Real-Time Threat Scanner",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = scanner.realtimeMessage,
                    color = Color(0xFFCFD8DC),
                    fontSize = 13.sp,
                    lineHeight = 21.sp
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Status Badge
                Surface(
                    shape = RoundedCornerShape(50),
                    color = statusColor.copy(alpha = 0.15f)
                ) {

                    Text(
                        text = scanner.scannerStatus,
                        color = statusColor,
                        modifier = Modifier.padding(
                            horizontal = 18.dp,
                            vertical = 8.dp
                        ),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(28.dp))

                // Metrics Section
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    RealtimeMetricItem(
                        icon = Icons.Default.Security,
                        value = "${scanner.scannedFiles}",
                        label = "Scanned"
                    )

                    RealtimeMetricItem(
                        icon = Icons.Default.BugReport,
                        value = "${scanner.blockedThreats}",
                        label = "Blocked"
                    )

                    RealtimeMetricItem(
                        icon = Icons.Default.Shield,
                        value = "${scanner.activeProcesses}",
                        label = "Processes"
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Performance Panel
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color.White.copy(alpha = 0.06f))
                        .padding(18.dp)
                ) {

                    Column {

                        Text(
                            text = "Scanner Performance",
                            color = Color.White,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold
                        )

                        Spacer(modifier = Modifier.height(18.dp))

                        PerformanceRow(
                            icon = Icons.Default.Memory,
                            title = "Memory Usage",
                            value = scanner.memoryUsage,
                            progress = 0.42f,
                            color = Color.Cyan
                        )

                        Spacer(modifier = Modifier.height(16.dp))

                        PerformanceRow(
                            icon = Icons.Default.WarningAmber,
                            title = "CPU Usage",
                            value = scanner.cpuUsage,
                            progress = 0.31f,
                            color = statusColor
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Action Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {

                    Button(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF00BCD4)
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Deep Scan")
                    }

                    OutlinedButton(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Monitor")
                    }
                }
            }
        }
    }
}

@Composable
private fun RealtimeMetricItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    value: String,
    label: String
) {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Box(
            modifier = Modifier
                .size(50.dp)
                .clip(CircleShape)
                .background(Color.White.copy(alpha = 0.08f)),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color.Cyan,
                modifier = Modifier.size(24.dp)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 16.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 11.sp
        )
    }
}

@Composable
private fun PerformanceRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    value: String,
    progress: Float,
    color: Color
) {

    Column {

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(20.dp)
            )

            Spacer(modifier = Modifier.width(10.dp))

            Text(
                text = title,
                color = Color.White,
                modifier = Modifier.weight(1f),
                fontSize = 13.sp
            )

            Text(
                text = value,
                color = color,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(8.dp))

        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp)
                .clip(RoundedCornerShape(50)),
            color = color,
            trackColor = Color(0xFF334155)
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

RealtimeScannerView(
    scanner = RealtimeScannerModel(
        scannerStatus = "Scanning",
        activeProcesses = 84,
        scannedFiles = 1248,
        blockedThreats = 6,
        cpuUsage = "31%",
        memoryUsage = "42%",
        realtimeMessage =
        "SentriX is actively monitoring running processes, " +
        "network traffic, downloaded files, and application behavior."
    )
)

*/
