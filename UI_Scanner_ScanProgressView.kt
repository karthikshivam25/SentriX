package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ScanProgressModel(
    val scanTitle: String,
    val currentFile: String,
    val scannedItems: Int,
    val totalItems: Int,
    val threatsDetected: Int,
    val progress: Float,
    val scanStatus: String
)

@Composable
fun ScanProgressView(
    scan: ScanProgressModel,
    modifier: Modifier = Modifier
) {

    val statusColor = when (scan.scanStatus) {
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

                // Scanner Icon
                Box(
                    modifier = Modifier
                        .size(88.dp)
                        .clip(CircleShape)
                        .background(statusColor.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = statusColor,
                        modifier = Modifier.size(42.dp)
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Text(
                    text = scan.scanTitle,
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = scan.currentFile,
                    color = Color(0xFFCFD8DC),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )

                Spacer(modifier = Modifier.height(28.dp))

                // Progress Indicator
                LinearProgressIndicator(
                    progress = { scan.progress },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(12.dp)
                        .clip(RoundedCornerShape(50)),
                    color = statusColor,
                    trackColor = Color(0xFF334155)
                )

                Spacer(modifier = Modifier.height(14.dp))

                Text(
                    text = "${(scan.progress * 100).toInt()}% Completed",
                    color = statusColor,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(28.dp))

                // Scan Metrics
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    ScanMetricItem(
                        icon = Icons.Default.Storage,
                        value = "${scan.scannedItems}/${scan.totalItems}",
                        label = "Files"
                    )

                    ScanMetricItem(
                        icon = Icons.Default.Verified,
                        value = "${scan.threatsDetected}",
                        label = "Threats"
                    )

                    ScanMetricItem(
                        icon = Icons.Default.Shield,
                        value = scan.scanStatus,
                        label = "Status"
                    )
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Footer Status
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color.White.copy(alpha = 0.06f))
                        .padding(16.dp)
                ) {

                    Text(
                        text =
                        "SentriX is continuously inspecting applications, " +
                                "downloads, permissions, and device behavior " +
                                "for suspicious threats and vulnerabilities.",
                        color = Color(0xFFECEFF1),
                        fontSize = 13.sp,
                        lineHeight = 20.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun ScanMetricItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    value: String,
    label: String
) {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Box(
            modifier = Modifier
                .size(48.dp)
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
            fontSize = 15.sp,
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

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

ScanProgressView(
    scan = ScanProgressModel(
        scanTitle = "Deep Threat Scan",
        currentFile = "Scanning: Android/data/cache/system.apk",
        scannedItems = 482,
        totalItems = 1260,
        threatsDetected = 3,
        progress = 0.72f,
        scanStatus = "Scanning"
    )
)

*/
