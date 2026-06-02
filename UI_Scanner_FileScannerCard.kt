package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class FileScannerModel(
    val fileName: String,
    val fileType: String,
    val fileSize: String,
    val scanStatus: String,
    val threatLevel: String,
    val fileLocation: String,
    val lastScanned: String,
    val scanMessage: String
)

@Composable
fun FileScannerCard(
    file: FileScannerModel,
    modifier: Modifier = Modifier
) {

    val threatColor = when (file.threatLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        "Safe" -> Color(0xFF00E676)
        else -> Color.Cyan
    }

    val fileIcon = when (file.fileType) {
        "PDF" -> Icons.Default.Article
        "ZIP" -> Icons.Default.FolderZip
        "DOC" -> Icons.Default.Description
        else -> Icons.Default.InsertDriveFile
    }

    val statusIcon: ImageVector = when (file.threatLevel) {
        "Critical" -> Icons.Default.WarningAmber
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
                            .background(threatColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = fileIcon,
                            contentDescription = null,
                            tint = threatColor,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = file.fileName,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = file.fileLocation,
                            color = Color(0xFF90A4AE),
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = threatColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = file.threatLevel,
                            color = threatColor,
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

                FileInfoRow(
                    label = "File Type",
                    value = file.fileType,
                    valueColor = Color.White
                )

                FileInfoRow(
                    label = "File Size",
                    value = file.fileSize,
                    valueColor = Color.White
                )

                FileInfoRow(
                    label = "Scan Status",
                    value = file.scanStatus,
                    valueColor = threatColor
                )

                FileInfoRow(
                    label = "Last Scanned",
                    value = file.lastScanned,
                    valueColor = Color.White
                )

                Spacer(modifier = Modifier.height(22.dp))

                // Security Analysis Box
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
                            tint = threatColor,
                            modifier = Modifier.size(24.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Column {

                            Text(
                                text = "File Security Analysis",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )

                            Spacer(modifier = Modifier.height(8.dp))

                            Text(
                                text = file.scanMessage,
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

                    FileMetricItem(
                        icon = fileIcon,
                        value = file.fileType,
                        label = "Format"
                    )

                    FileMetricItem(
                        icon = Icons.Default.Security,
                        value = file.scanStatus,
                        label = "Status"
                    )

                    FileMetricItem(
                        icon = Icons.Default.WarningAmber,
                        value = file.threatLevel,
                        label = "Threat"
                    )
                }

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

                        Text(text = "Inspect")
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
private fun FileInfoRow(
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
private fun FileMetricItem(
    icon: ImageVector,
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

FileScannerCard(
    file = FileScannerModel(
        fileName = "invoice_report.zip",
        fileType = "ZIP",
        fileSize = "18.4 MB",
        scanStatus = "Threat Detected",
        threatLevel = "High",
        fileLocation = "/Downloads/Suspicious",
        lastScanned = "12:42 PM",
        scanMessage =
        "Compressed archive contains suspicious executable " +
        "scripts and hidden payload patterns commonly associated " +
        "with malicious file delivery."
    )
)

*/
