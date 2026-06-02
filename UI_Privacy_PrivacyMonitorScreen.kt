package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class PrivacyMonitorModel(
    val appName: String,
    val accessType: String,
    val lastAccessed: String,
    val riskLevel: String,
    val icon: ImageVector
)

@Composable
fun PrivacyMonitorScreen(
    privacyLogs: List<PrivacyMonitorModel>
) {

    Scaffold(
        containerColor = Color(0xFF0B1120),
        topBar = {
            PrivacyMonitorTopBar()
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
                PrivacyOverviewCard()
            }

            item {
                PrivacySecurityStatusCard()
            }

            item {

                Text(
                    text = "Recent Privacy Activity",
                    color = Color.White,
                    fontSize = 19.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(privacyLogs) { log ->

                PrivacyAccessLogCard(
                    log = log
                )
            }

            item {
                Spacer(modifier = Modifier.height(30.dp))
            }
        }
    }
}

@Composable
private fun PrivacyMonitorTopBar() {

    TopAppBar(
        title = {

            Column {

                Text(
                    text = "Privacy Monitor",
                    color = Color.White,
                    fontWeight = FontWeight.Bold
                )

                Text(
                    text = "Real-time permission tracking",
                    color = Color(0xFF90A4AE),
                    fontSize = 12.sp
                )
            }
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = Color(0xFF0F172A)
        ),
        actions = {

            IconButton(
                onClick = { }
            ) {

                Icon(
                    imageVector = Icons.Default.Notifications,
                    contentDescription = null,
                    tint = Color.White
                )
            }
        }
    )
}

@Composable
private fun PrivacyOverviewCard() {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
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
                            Color(0xFF172554)
                        )
                    )
                )
                .padding(22.dp)
        ) {

            Column {

                Text(
                    text = "Privacy Protection Score",
                    color = Color(0xFFCFD8DC),
                    fontSize = 14.sp
                )

                Spacer(modifier = Modifier.height(12.dp))

                Text(
                    text = "92%",
                    color = Color(0xFF00E676),
                    fontSize = 40.sp,
                    fontWeight = FontWeight.ExtraBold
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text =
                    "SentriX is actively monitoring app behavior " +
                            "and preventing suspicious privacy access attempts.",
                    color = Color.White,
                    fontSize = 13.sp,
                    lineHeight = 21.sp
                )
            }
        }
    }
}

@Composable
private fun PrivacySecurityStatusCard() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        SecurityMiniCard(
            title = "Protected",
            value = "48 Apps",
            icon = Icons.Default.Security,
            color = Color(0xFF00E676),
            modifier = Modifier.weight(1f)
        )

        SecurityMiniCard(
            title = "Warnings",
            value = "3 Risks",
            icon = Icons.Default.WarningAmber,
            color = Color(0xFFFFC400),
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun SecurityMiniCard(
    title: String,
    value: String,
    icon: ImageVector,
    color: Color,
    modifier: Modifier = Modifier
) {

    Card(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF111827)
        )
    ) {

        Column(
            modifier = Modifier.padding(18.dp)
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(28.dp)
            )

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = value,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 18.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = title,
                color = Color(0xFF90A4AE),
                fontSize = 12.sp
            )
        }
    }
}

@Composable
private fun PrivacyAccessLogCard(
    log: PrivacyMonitorModel
) {

    val riskColor = when (log.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
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
                    .size(54.dp)
                    .background(
                        color = riskColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(16.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = log.icon,
                    contentDescription = null,
                    tint = riskColor,
                    modifier = Modifier.size(28.dp)
                )
            }

            Spacer(modifier = Modifier.width(16.dp))

            Column(
                modifier = Modifier.weight(1f)
            ) {

                Text(
                    text = log.appName,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = log.accessType,
                    color = Color(0xFFB0BEC5),
                    fontSize = 13.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = "Last Accessed: ${log.lastAccessed}",
                    color = Color(0xFF78909C),
                    fontSize = 11.sp
                )
            }

            Surface(
                shape = RoundedCornerShape(50),
                color = riskColor.copy(alpha = 0.15f)
            ) {

                Text(
                    text = log.riskLevel,
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
    }
}

/*
---------------------------------------------------
SAMPLE PREVIEW DATA
---------------------------------------------------

val privacyLogs = listOf(

    PrivacyMonitorModel(
        appName = "Instagram",
        accessType = "Camera & Microphone Access",
        lastAccessed = "2 mins ago",
        riskLevel = "Medium",
        icon = Icons.Default.CameraAlt
    ),

    PrivacyMonitorModel(
        appName = "Maps",
        accessType = "Background Location Tracking",
        lastAccessed = "5 mins ago",
        riskLevel = "High",
        icon = Icons.Default.LocationOn
    ),

    PrivacyMonitorModel(
        appName = "Telegram",
        accessType = "Storage File Access",
        lastAccessed = "12 mins ago",
        riskLevel = "Low",
        icon = Icons.Default.Folder
    )
)

PrivacyMonitorScreen(
    privacyLogs = privacyLogs
)

*/
