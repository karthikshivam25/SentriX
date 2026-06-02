package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
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

data class ScanSummaryModel(
    val totalFilesScanned: Int,
    val threatsDetected: Int,
    val protectedApps: Int,
    val suspiciousFiles: Int,
    val scanDuration: String,
    val lastScanTime: String,
    val securityScore: Int
)

@Composable
fun ScanSummaryCard(
    summary: ScanSummaryModel,
    modifier: Modifier = Modifier
) {

    val securityColor = when {
        summary.securityScore >= 85 -> Color(0xFF00E676)
        summary.securityScore >= 60 -> Color(0xFFFFC400)
        else -> Color(0xFFFF5252)
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
                modifier = Modifier.fillMaxWidth()
            ) {

                // Header
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .clip(CircleShape)
                            .background(securityColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = securityColor,
                            modifier = Modifier.size(34.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = "Scan Summary",
                            color = Color.White,
                            fontSize = 22.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "SentriX security inspection report",
                            color = Color(0xFF90A4AE),
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = securityColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = "${summary.securityScore}/100",
                            color = securityColor,
                            modifier = Modifier.padding(
                                horizontal = 14.dp,
                                vertical = 8.dp
                            ),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                // Security Score
                Text(
                    text = "Device Security Score",
                    color = Color(0xFFCFD8DC),
                    fontSize = 14.sp
                )

                Spacer(modifier = Modifier.height(10.dp))

                LinearProgressIndicator(
                    progress = { summary.securityScore / 100f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(10.dp)
                        .clip(RoundedCornerShape(50)),
                    color = securityColor,
                    trackColor = Color(0xFF334155)
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "${summary.securityScore}% Protected",
                    color = securityColor,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(28.dp))

                // Statistics Grid
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    SummaryMetricItem(
                        icon = Icons.Default.Folder,
                        value = "${summary.totalFilesScanned}",
                        label = "Scanned"
                    )

                    SummaryMetricItem(
                        icon = Icons.Default.WarningAmber,
                        value = "${summary.threatsDetected}",
                        label = "Threats"
                    )

                    SummaryMetricItem(
                        icon = Icons.Default.Security,
                        value = "${summary.protectedApps}",
                        label = "Protected"
                    )

                    SummaryMetricItem(
                        icon = Icons.Default.CheckCircle,
                        value = "${summary.suspiciousFiles}",
                        label = "Flagged"
                    )
                }

                Spacer(modifier = Modifier.height(28.dp))

                // Scan Details
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color.White.copy(alpha = 0.06f))
                        .padding(18.dp)
                ) {

                    Column {

                        SummaryInfoRow(
                            label = "Scan Duration",
                            value = summary.scanDuration
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        SummaryInfoRow(
                            label = "Last Scan",
                            value = summary.lastScanTime
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Footer Message
                Text(
                    text =
                    "SentriX completed a deep system inspection and " +
                            "continuously monitors device behavior for malware, " +
                            "unsafe applications, and suspicious activity.",
                    color = Color(0xFFECEFF1),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Actions
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

                        Text(text = "Run Again")
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

                        Text(text = "View Report")
                    }
                }
            }
        }
    }
}

@Composable
private fun SummaryMetricItem(
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

@Composable
private fun SummaryInfoRow(
    label: String,
    value: String
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 13.sp
        )

        Text(
            text = value,
            color = Color.White,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

ScanSummaryCard(
    summary = ScanSummaryModel(
        totalFilesScanned = 4821,
        threatsDetected = 6,
        protectedApps = 48,
        suspiciousFiles = 14,
        scanDuration = "08m 42s",
        lastScanTime = "Today, 12:48 PM",
        securityScore = 91
    )
)

*/
