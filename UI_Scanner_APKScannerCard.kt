package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FilePresent
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class APKScannerModel(
    val appName: String,
    val packageName: String,
    val apkSize: String,
    val scanStatus: String,
    val riskLevel: String,
    val detectedThreats: Int,
    val scanMessage: String,
    val lastScanned: String
)

@Composable
fun APKScannerCard(
    apk: APKScannerModel,
    modifier: Modifier = Modifier
) {

    val riskColor = when (apk.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        "Safe" -> Color(0xFF00E676)
        else -> Color.Cyan
    }

    val statusIcon = when (apk.riskLevel) {
        "Critical" -> Icons.Default.BugReport
        "High" -> Icons.Default.WarningAmber
        "Medium" -> Icons.Default.WarningAmber
        "Safe" -> Icons.Default.CheckCircle
        else -> Icons.Default.Security
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(26.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF111827),
                            Color(0xFF0F172A)
                        )
                    )
                )
                .padding(22.dp)
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
                            .size(60.dp)
                            .clip(CircleShape)
                            .background(riskColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Android,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = apk.appName,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = apk.packageName,
                            color = Color(0xFF90A4AE),
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = riskColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = apk.riskLevel,
                            color = riskColor,
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 6.dp
                            ),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                APKInfoRow(
                    label = "APK Size",
                    value = apk.apkSize,
                    valueColor = Color.White
                )

                APKInfoRow(
                    label = "Scan Status",
                    value = apk.scanStatus,
                    valueColor = riskColor
                )

                APKInfoRow(
                    label = "Threats Detected",
                    value = "${apk.detectedThreats}",
                    valueColor = riskColor
                )

                APKInfoRow(
                    label = "Last Scanned",
                    value = apk.lastScanned,
                    valueColor = Color.White
                )

                Spacer(modifier = Modifier.height(22.dp))

                // Scan Analysis Panel
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color(0xFF1E293B))
                        .padding(16.dp)
                ) {

                    Row(
                        verticalAlignment = Alignment.Top
                    ) {

                        Icon(
                            imageVector = statusIcon,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "APK Security Analysis",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = apk.scanMessage,
                                color = Color(0xFFECEFF1),
                                fontSize = 13.sp,
                                lineHeight = 20.sp
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Metrics
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    APKMetricItem(
                        icon = Icons.Default.FilePresent,
                        value = apk.apkSize,
                        label = "Package"
                    )

                    APKMetricItem(
                        icon = Icons.Default.Security,
                        value = apk.scanStatus,
                        label = "Status"
                    )

                    APKMetricItem(
                        icon = Icons.Default.BugReport,
                        value = "${apk.detectedThreats}",
                        label = "Threats"
                    )
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

                        Text(text = "Analyze")
                    }

                    OutlinedButton(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.Red
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.WarningAmber,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Quarantine")
                    }
                }
            }
        }
    }
}

@Composable
private fun APKInfoRow(
    label: String,
    value: String,
    valueColor: Color
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 13.sp
        )

        Text(
            text = value,
            color = valueColor,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun APKMetricItem(
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
                modifier = Modifier.size(22.dp)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 13.sp,
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

APKScannerCard(
    apk = APKScannerModel(
        appName = "Unknown Installer",
        packageName = "com.external.installer",
        apkSize = "24.6 MB",
        scanStatus = "Threat Detected",
        riskLevel = "High",
        detectedThreats = 3,
        scanMessage =
        "Suspicious APK behavior detected including hidden " +
        "background services and excessive permission requests.",
        lastScanned = "12:14 PM"
    )
)

*/
