package com.sentrix.ui.threats

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ThreatItem(
    val id: Int,
    val title: String,
    val description: String,
    val severity: ThreatSeverity,
    val time: String,
    val resolved: Boolean
)

enum class ThreatSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatCenterScreen() {

    val threatList = remember {
        mutableStateListOf(
            ThreatItem(
                1,
                "Ransomware Signature Detected",
                "Potential ransomware behavior blocked before execution.",
                ThreatSeverity.CRITICAL,
                "2 mins ago",
                false
            ),
            ThreatItem(
                2,
                "Suspicious Network Activity",
                "Outbound traffic detected to unknown remote host.",
                ThreatSeverity.HIGH,
                "12 mins ago",
                false
            ),
            ThreatItem(
                3,
                "Malicious APK Prevented",
                "Application installation stopped due to malware risk.",
                ThreatSeverity.MEDIUM,
                "28 mins ago",
                true
            ),
            ThreatItem(
                4,
                "Unsafe Wi-Fi Warning",
                "Connected network lacks proper encryption.",
                ThreatSeverity.LOW,
                "1 hour ago",
                true
            )
        )
    }

    var selectedFilter by remember { mutableStateOf("All") }

    val filteredThreats = threatList.filter {
        when (selectedFilter) {
            "Active" -> !it.resolved
            "Resolved" -> it.resolved
            else -> true
        }
    }

    val criticalCount = threatList.count { it.severity == ThreatSeverity.CRITICAL }
    val activeThreats = threatList.count { !it.resolved }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Threat Center",
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {
                    IconButton(onClick = { }) {
                        Icon(
                            imageVector = Icons.Default.Refresh,
                            contentDescription = "Refresh"
                        )
                    }
                }
            )
        },
        containerColor = Color(0xFF0B1020)
    ) { paddingValues ->

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {

            item {
                Spacer(modifier = Modifier.height(8.dp))
            }

            item {
                ThreatOverviewCard(
                    activeThreats = activeThreats,
                    criticalThreats = criticalCount
                )
            }

            item {
                ThreatFilterRow(
                    selectedFilter = selectedFilter,
                    onFilterSelected = {
                        selectedFilter = it
                    }
                )
            }

            item {
                Text(
                    text = "Recent Threat Activity",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(filteredThreats) { threat ->
                ThreatItemCard(threat = threat)
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

@Composable
fun ThreatOverviewCard(
    activeThreats: Int,
    criticalThreats: Int
) {
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
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF1A1F35),
                            Color(0xFF101728)
                        )
                    )
                )
                .padding(20.dp)
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
                        text = "Threat Intelligence",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    ThreatStatItem(
                        value = activeThreats.toString(),
                        label = "Active Threats",
                        color = Color(0xFFFF5252)
                    )

                    ThreatStatItem(
                        value = criticalThreats.toString(),
                        label = "Critical",
                        color = Color(0xFFFF1744)
                    )

                    ThreatStatItem(
                        value = "98%",
                        label = "Protection",
                        color = Color(0xFF00E676)
                    )
                }
            }
        }
    }
}

@Composable
fun ThreatStatItem(
    value: String,
    label: String,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Text(
            text = value,
            color = color,
            fontSize = 22.sp,
            fontWeight = FontWeight.ExtraBold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = label,
            color = Color.LightGray,
            fontSize = 12.sp
        )
    }
}

@Composable
fun ThreatFilterRow(
    selectedFilter: String,
    onFilterSelected: (String) -> Unit
) {

    val filters = listOf("All", "Active", "Resolved")

    Row(
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {

        filters.forEach { filter ->

            val isSelected = selectedFilter == filter

            Surface(
                modifier = Modifier
                    .clip(RoundedCornerShape(50))
                    .clickable {
                        onFilterSelected(filter)
                    },
                color = if (isSelected)
                    Color(0xFF00E5FF)
                else
                    Color(0xFF1A2238)
            ) {

                Text(
                    text = filter,
                    modifier = Modifier.padding(
                        horizontal = 18.dp,
                        vertical = 10.dp
                    ),
                    color = if (isSelected)
                        Color.Black
                    else
                        Color.White,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }
    }
}

@Composable
fun ThreatItemCard(
    threat: ThreatItem
) {

    val severityColor = when (threat.severity) {
        ThreatSeverity.LOW -> Color(0xFF00E676)
        ThreatSeverity.MEDIUM -> Color(0xFFFFC400)
        ThreatSeverity.HIGH -> Color(0xFFFF9100)
        ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF151C2E)
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
                        .size(14.dp)
                        .clip(CircleShape)
                        .background(severityColor)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Text(
                    text = threat.severity.name,
                    color = severityColor,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )

                Spacer(modifier = Modifier.weight(1f))

                Text(
                    text = threat.time,
                    color = Color.Gray,
                    fontSize = 12.sp
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = threat.title,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 17.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = threat.description,
                color = Color.LightGray,
                fontSize = 14.sp,
                lineHeight = 20.sp
            )

            Spacer(modifier = Modifier.height(16.dp))

            AnimatedVisibility(
                visible = threat.resolved,
                enter = fadeIn(),
                exit = fadeOut()
            ) {

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = Color(0xFF00E676),
                        modifier = Modifier.size(18.dp)
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = "Threat Neutralized",
                        color = Color(0xFF00E676),
                        fontWeight = FontWeight.Medium,
                        fontSize = 13.sp
                    )
                }
            }

            AnimatedVisibility(
                visible = !threat.resolved,
                enter = fadeIn(),
                exit = fadeOut()
            ) {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {

                    OutlinedButton(
                        onClick = { },
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color(0xFF00E5FF)
                        )
                    ) {
                        Icon(
                            imageVector = Icons.Default.Visibility,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Investigate")
                    }
                }
            }
        }
    }
}
