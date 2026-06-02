package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
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

data class ScanResultItemModel(
    val title: String,
    val description: String,
    val threatLevel: String,
    val scannedAt: String,
    val affectedArea: String
)

@Composable
fun ScanResultsView(
    results: List<ScanResultItemModel>,
    modifier: Modifier = Modifier
) {

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
                            Color(0xFF111827)
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
                            .size(58.dp)
                            .clip(CircleShape)
                            .background(Color.Cyan.copy(alpha = 0.12f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = Color.Cyan,
                            modifier = Modifier.size(30.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column {

                        Text(
                            text = "Threat Scan Results",
                            color = Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "Security analysis and detection report",
                            color = Color(0xFF90A4AE),
                            fontSize = 13.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {

                    items(results) { result ->

                        ScanResultItemCard(
                            result = result
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanResultItemCard(
    result: ScanResultItemModel
) {

    val threatColor = when (result.threatLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        "Safe" -> Color(0xFF00E676)
        else -> Color.Cyan
    }

    val threatIcon = when (result.threatLevel) {
        "Critical" -> Icons.Default.Error
        "High" -> Icons.Default.BugReport
        "Medium" -> Icons.Default.WarningAmber
        "Safe" -> Icons.Default.CheckCircle
        else -> Icons.Default.Security
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF1E293B)
        )
    ) {

        Column(
            modifier = Modifier.padding(18.dp)
        ) {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(52.dp)
                        .clip(CircleShape)
                        .background(threatColor.copy(alpha = 0.15f)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = threatIcon,
                        contentDescription = null,
                        tint = threatColor,
                        modifier = Modifier.size(28.dp)
                    )
                }

                Spacer(modifier = Modifier.width(14.dp))

                Column(
                    modifier = Modifier.weight(1f)
                ) {

                    Text(
                        text = result.title,
                        color = Color.White,
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = result.affectedArea,
                        color = Color(0xFF90A4AE),
                        fontSize = 12.sp
                    )
                }

                Surface(
                    shape = RoundedCornerShape(50),
                    color = threatColor.copy(alpha = 0.15f)
                ) {

                    Text(
                        text = result.threatLevel,
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

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = result.description,
                color = Color(0xFFECEFF1),
                fontSize = 13.sp,
                lineHeight = 20.sp
            )

            Spacer(modifier = Modifier.height(18.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {

                Text(
                    text = "Scanned: ${result.scannedAt}",
                    color = Color(0xFF78909C),
                    fontSize = 11.sp
                )

                TextButton(
                    onClick = { }
                ) {

                    Text(
                        text = "View Details",
                        color = Color.Cyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }
        }
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

val scanResults = listOf(

    ScanResultItemModel(
        title = "Background Tracker Detected",
        description =
        "A hidden background tracker was identified accessing " +
        "location services repeatedly without active user interaction.",
        threatLevel = "High",
        scannedAt = "11:42 AM",
        affectedArea = "Location Services"
    ),

    ScanResultItemModel(
        title = "Unsafe APK Signature",
        description =
        "An application package contains an unverified digital " +
        "signature and may pose a security threat.",
        threatLevel = "Critical",
        scannedAt = "11:48 AM",
        affectedArea = "Downloaded Files"
    ),

    ScanResultItemModel(
        title = "Permission Scan Completed",
        description =
        "All sensitive permissions were inspected and no malicious " +
        "behavior patterns were detected.",
        threatLevel = "Safe",
        scannedAt = "11:53 AM",
        affectedArea = "Permission Manager"
    )
)

ScanResultsView(
    results = scanResults
)

*/
