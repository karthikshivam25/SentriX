package com.sentrix.ui.vpn

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class VPNStatsData(
    val downloadSpeed: String,
    val uploadSpeed: String,
    val ping: Int,
    val securityScore: Int,
    val dataProtected: String
)

@Composable
fun VPNStatsCard(

    data: VPNStatsData,
    modifier: Modifier = Modifier
) {

    val animatedProgress by animateFloatAsState(
        targetValue = data.securityScore / 100f,
        label = "security_progress"
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
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = "VPN Statistics",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                Spacer(modifier = Modifier.height(28.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    VPNSecurityMeter(
                        score = data.securityScore,
                        progress = animatedProgress
                    )

                    Column(
                        verticalArrangement = Arrangement.spacedBy(16.dp)
                    ) {

                        VPNStatInfo(
                            title = "Download",
                            value = data.downloadSpeed,
                            icon = Icons.Default.Download,
                            valueColor = Color(0xFF00E676)
                        )

                        VPNStatInfo(
                            title = "Upload",
                            value = data.uploadSpeed,
                            icon = Icons.Default.Upload,
                            valueColor = Color(0xFF00E5FF)
                        )

                        VPNStatInfo(
                            title = "Ping",
                            value = "${data.ping} ms",
                            icon = Icons.Default.Speed,
                            valueColor = Color.White
                        )
                    }
                }

                Spacer(modifier = Modifier.height(26.dp))

                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = Color(0xFF111827)
                ) {

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(
                                horizontal = 18.dp,
                                vertical = 14.dp
                            ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = Color(0xFF00E676)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "Protected Traffic",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )

                            Spacer(modifier = Modifier.height(4.dp))

                            Text(
                                text = "${data.dataProtected} encrypted successfully",
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
fun VPNSecurityMeter(

    score: Int,
    progress: Float
) {

    Box(
        modifier = Modifier.size(150.dp),
        contentAlignment = Alignment.Center
    ) {

        Canvas(
            modifier = Modifier.fillMaxSize()
        ) {

            val strokeWidth = 16.dp.toPx()

            drawArc(
                color = Color(0xFF2A3550),
                startAngle = 135f,
                sweepAngle = 270f,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height)
            )

            drawArc(
                brush = Brush.sweepGradient(
                    colors = listOf(
                        Color(0xFF00E5FF),
                        Color(0xFF00E676)
                    )
                ),
                startAngle = 135f,
                sweepAngle = 270f * progress,
                useCenter = false,
                style = Stroke(
                    width = strokeWidth,
                    cap = StrokeCap.Round
                ),
                size = Size(size.width, size.height)
            )
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Text(
                text = "$score%",
                color = Color.White,
                fontSize = 28.sp,
                fontWeight = FontWeight.ExtraBold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Secure",
                color = Color.Gray,
                fontSize = 13.sp
            )
        }
    }
}

@Composable
fun VPNStatInfo(

    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    valueColor: Color
) {

    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {

        Surface(
            shape = RoundedCornerShape(14.dp),
            color = Color(0xFF1E293B)
        ) {

            Box(
                modifier = Modifier.padding(10.dp),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = Color(0xFF00E5FF),
                    modifier = Modifier.size(18.dp)
                )
            }
        }

        Spacer(modifier = Modifier.width(12.dp))

        Column {

            Text(
                text = title,
                color = Color.Gray,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(3.dp))

            Text(
                text = value,
                color = valueColor,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun VPNStatsPreviewData(): VPNStatsData {

    return VPNStatsData(
        downloadSpeed = "182 Mbps",
        uploadSpeed = "94 Mbps",
        ping = 42,
        securityScore = 98,
        dataProtected = "12.4 GB"
    )
}
