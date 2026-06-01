package com.sentrix.ui.screens.dashboard.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Scanner
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
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

@Composable
fun RecentScanCard(
    modifier: Modifier = Modifier,
    lastScanTime: String = "Today, 10:42 AM",
    scannedFiles: Int = 12458,
    detectedThreats: Int = 2,
    scanProgress: Float = 0.92f,
    scanStatus: String = "Scan Completed"
) {

    val infiniteTransition = rememberInfiniteTransition(
        label = "recent_scan_glow"
    )

    val glowAlpha by infiniteTransition.animateFloat(
        initialValue = 0.18f,
        targetValue = 0.42f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 2100,
                easing = FastOutSlowInEasing
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "glow_alpha"
    )

    val accentColor = if (detectedThreats == 0) {
        Color(0xFF00E676)
    } else {
        Color(0xFFFFC107)
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
                            accentColor.copy(alpha = glowAlpha),
                            accentColor.copy(alpha = glowAlpha * 0.35f)
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
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(56.dp)
                            .clip(CircleShape)
                            .background(
                                accentColor.copy(alpha = 0.14f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Scanner,
                            contentDescription = "Recent Scan",
                            tint = accentColor,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column {

                        Text(
                            text = "Recent Security Scan",
                            color = Color.White,
                            fontSize = 21.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = scanStatus,
                            color = accentColor,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(26.dp))

                // ----------------------------------------
                // SCAN STATUS CONTAINER
                // ----------------------------------------

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(26.dp))
                        .background(
                            Color.White.copy(alpha = 0.04f)
                        )
                        .padding(22.dp)
                ) {

                    Column {

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Column {

                                Text(
                                    text = "Last Scan",
                                    color = Color(0xFF9CA3AF),
                                    fontSize = 13.sp
                                )

                                Spacer(modifier = Modifier.height(6.dp))

                                Text(
                                    text = lastScanTime,
                                    color = Color.White,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }

                            Icon(
                                imageVector = if (detectedThreats == 0) {
                                    Icons.Default.CheckCircle
                                } else {
                                    Icons.Default.WarningAmber
                                },
                                contentDescription = "Scan Result",
                                tint = accentColor,
                                modifier = Modifier.size(34.dp)
                            )
                        }

                        Spacer(modifier = Modifier.height(24.dp))

                        LinearProgressIndicator(
                            progress = { scanProgress },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(10.dp)
                                .clip(RoundedCornerShape(50)),
                            color = accentColor,
                            trackColor = Color.White.copy(alpha = 0.08f)
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = "${(scanProgress * 100).toInt()}% completed",
                            color = Color(0xFF9CA3AF),
                            fontSize = 12.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // ----------------------------------------
                // SCAN STATS
                // ----------------------------------------

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    ScanStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Files Scanned",
                        value = scannedFiles.toString(),
                        accentColor = Color(0xFF00D9FF)
                    )

                    ScanStatItem(
                        modifier = Modifier.weight(1f),
                        title = "Threats Found",
                        value = detectedThreats.toString(),
                        accentColor = accentColor
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanStatItem(
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
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold
        )
    }
}
