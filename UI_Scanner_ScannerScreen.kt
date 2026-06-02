package com.sentrix.ui.scanner

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ScanResultModel(
    val title: String,
    val description: String,
    val status: String
)

@Composable
fun ScannerScreen() {

    var scanProgress by remember {
        mutableFloatStateOf(0.72f)
    }

    val scanResults = listOf(

        ScanResultModel(
            title = "Malware Detection",
            description = "No malware signatures detected",
            status = "Safe"
        ),

        ScanResultModel(
            title = "Application Security",
            description = "3 applications require permission review",
            status = "Warning"
        ),

        ScanResultModel(
            title = "Storage Inspection",
            description = "Protected sensitive downloaded files",
            status = "Secure"
        ),

        ScanResultModel(
            title = "Background Activity",
            description = "Suspicious background tracker detected",
            status = "Critical"
        )
    )

    Scaffold(
        containerColor = Color(0xFF0B1120),
        topBar = {
            ScannerTopBar()
        }
    ) { paddingValues ->

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(Color(0xFF0B1120)),
            contentPadding = PaddingValues(
                horizontal = 18.dp,
                vertical = 20.dp
            ),
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {

            item {

                ScannerOverviewCard(
                    progress = scanProgress
                )
            }

            item {

                ScannerStatsSection()
            }

            item {

                Text(
                    text = "Security Scan Results",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(scanResults.size) { index ->

                ScanResultCard(
                    result = scanResults[index]
                )
            }

            item {

                Spacer(modifier = Modifier.height(30.dp))
            }
        }
    }
}

@Composable
private fun ScannerTopBar() {

    TopAppBar(
        title = {

            Column {

                Text(
                    text = "Threat Scanner",
                    color = Color.White,
                    fontWeight = FontWeight.Bold
                )

                Text(
                    text = "Real-time security inspection",
                    color = Color(0xFF90A4AE),
                    fontSize = 12.sp
                )
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = Color(0xFF0F172A)
        )
    )
}

@Composable
private fun ScannerOverviewCard(
    progress: Float
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
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
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {

                Box(
                    modifier = Modifier
                        .size(88.dp)
                        .clip(CircleShape)
                        .background(Color.Cyan.copy(alpha = 0.12f)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = Color.Cyan,
                        modifier = Modifier.size(42.dp)
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Text(
                    text = "Device Security Scan",
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text =
                    "SentriX is actively scanning applications, " +
                            "permissions, downloads, and background services.",
                    color = Color(0xFFCFD8DC),
                    fontSize = 13.sp,
                    lineHeight = 21.sp
                )

                Spacer(modifier = Modifier.height(24.dp))

                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(10.dp)
                        .clip(RoundedCornerShape(50)),
                    color = Color.Cyan,
                    trackColor = Color(0xFF334155)
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "${(progress * 100).toInt()}% Completed",
                    color = Color.Cyan,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { },
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF00BCD4)
                    )
                ) {

                    Icon(
                        imageVector = Icons.Default.PlayArrow,
                        contentDescription = null
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(text = "Start Deep Scan")
                }
            }
        }
    }
}

@Composable
private fun ScannerStatsSection() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        ScannerStatCard(
            title = "Protected",
            value = "48 Apps",
            icon = Icons.Default.Shield,
            color = Color(0xFF00E676),
            modifier = Modifier.weight(1f)
        )

        ScannerStatCard(
            title = "Threats",
            value = "3 Found",
            icon = Icons.Default.WarningAmber,
            color = Color(0xFFFF9100),
            modifier = Modifier.weight(1f)
        )

        ScannerStatCard(
            title = "Scanned",
            value = "126 Files",
            icon = Icons.Default.Folder,
            color = Color.Cyan,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun ScannerStatCard(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color,
    modifier: Modifier = Modifier
) {

    Card(
        modifier = modifier,
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        )
    ) {

        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(28.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = value,
                color = Color.White,
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = title,
                color = Color(0xFF90A4AE),
                fontSize = 11.sp
            )
        }
    }
}

@Composable
private fun ScanResultCard(
    result: ScanResultModel
) {

    val statusColor = when (result.status) {
        "Critical" -> Color(0xFFFF1744)
        "Warning" -> Color(0xFFFFC400)
        "Secure" -> Color(0xFF00E676)
        else -> Color.Cyan
    }

    val statusIcon = when (result.status) {
        "Critical" -> Icons.Default.BugReport
        "Warning" -> Icons.Default.WarningAmber
        "Secure" -> Icons.Default.CheckCircle
        else -> Icons.Default.Security
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        )
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {

            Box(
                modifier = Modifier
                    .size(58.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.15f)),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = statusIcon,
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(30.dp)
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(
                modifier = Modifier.weight(1f)
            ) {

                Text(
                    text = result.title,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = result.description,
                    color = Color(0xFFB0BEC5),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
            }

            Surface(
                shape = RoundedCornerShape(50),
                color = statusColor.copy(alpha = 0.15f)
            ) {

                Text(
                    text = result.status,
                    color = statusColor,
                    modifier = Modifier.padding(
                        horizontal = 12.dp,
                        vertical = 6.dp
                    ),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
