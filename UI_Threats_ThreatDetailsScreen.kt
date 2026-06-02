package com.sentrix.ui.threats

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ThreatLog(
    val title: String,
    val timestamp: String,
    val completed: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatDetailsScreen(

    threatTitle: String = "Ransomware Signature Detected",
    severity: ThreatSeverity = ThreatSeverity.CRITICAL,
    description: String = "A ransomware-like behavior was detected and blocked before execution. System files remained protected and no unauthorized encryption activity was completed.",
    affectedDevice: String = "Samsung Galaxy S24 Ultra",
    detectedAt: String = "02 Jun 2026 • 10:24 AM",
    riskScore: Int = 94,
    resolved: Boolean = false,
    onBackPressed: () -> Unit = {}
) {

    val severityColor = when (severity) {
        ThreatSeverity.LOW -> Color(0xFF00E676)
        ThreatSeverity.MEDIUM -> Color(0xFFFFC400)
        ThreatSeverity.HIGH -> Color(0xFFFF9100)
        ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
    }

    val timeline = remember {
        listOf(
            ThreatLog(
                "Threat pattern identified",
                "10:24 AM",
                true
            ),
            ThreatLog(
                "Execution attempt blocked",
                "10:25 AM",
                true
            ),
            ThreatLog(
                "Network isolation activated",
                "10:25 AM",
                true
            ),
            ThreatLog(
                "Deep scan initiated",
                "10:26 AM",
                resolved
            )
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "Threat Details",
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBackPressed) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back"
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
                Spacer(modifier = Modifier.height(6.dp))
            }

            item {
                ThreatHeroCard(
                    title = threatTitle,
                    severity = severity.name,
                    severityColor = severityColor,
                    riskScore = riskScore,
                    resolved = resolved
                )
            }

            item {
                ThreatInfoSection(
                    title = "Threat Summary",
                    icon = Icons.Default.Description
                ) {
                    Text(
                        text = description,
                        color = Color.LightGray,
                        lineHeight = 22.sp
                    )
                }
            }

            item {
                ThreatInfoSection(
                    title = "Affected Device",
                    icon = Icons.Default.PhoneAndroid
                ) {

                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = Icons.Default.Devices,
                            contentDescription = null,
                            tint = Color(0xFF00E5FF)
                        )

                        Spacer(modifier = Modifier.width(10.dp))

                        Text(
                            text = affectedDevice,
                            color = Color.White,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            item {
                ThreatInfoSection(
                    title = "Detection Time",
                    icon = Icons.Default.AccessTime
                ) {

                    Text(
                        text = detectedAt,
                        color = Color.White,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            item {

                Text(
                    text = "Threat Timeline",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(timeline.size) { index ->
                ThreatTimelineItem(
                    log = timeline[index],
                    isLast = index == timeline.lastIndex
                )
            }

            item {

                AnimatedVisibility(
                    visible = !resolved,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut()
                ) {

                    Column {

                        ActionButtonsSection()

                        Spacer(modifier = Modifier.height(20.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun ThreatHeroCard(
    title: String,
    severity: String,
    severityColor: Color,
    riskScore: Int,
    resolved: Boolean
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

                    Box(
                        modifier = Modifier
                            .size(14.dp)
                            .clip(CircleShape)
                            .background(severityColor)
                    )

                    Spacer(modifier = Modifier.width(10.dp))

                    Text(
                        text = severity,
                        color = severityColor,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.weight(1f))

                    if (resolved) {

                        Surface(
                            shape = RoundedCornerShape(50),
                            color = Color(0x2200E676)
                        ) {

                            Text(
                                text = "RESOLVED",
                                modifier = Modifier.padding(
                                    horizontal = 12.dp,
                                    vertical = 6.dp
                                ),
                                color = Color(0xFF00E676),
                                fontSize = 12.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                Text(
                    text = title,
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(22.dp))

                Row(
                    horizontalArrangement = Arrangement.SpaceBetween,
                    modifier = Modifier.fillMaxWidth()
                ) {

                    Column {

                        Text(
                            text = "Risk Score",
                            color = Color.Gray,
                            fontSize = 13.sp
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Text(
                            text = "$riskScore%",
                            color = severityColor,
                            fontSize = 30.sp,
                            fontWeight = FontWeight.ExtraBold
                        )
                    }

                    CircularProgressIndicator(
                        progress = riskScore / 100f,
                        color = severityColor,
                        trackColor = Color.DarkGray,
                        strokeWidth = 8.dp,
                        modifier = Modifier.size(70.dp)
                    )
                }
            }
        }
    }
}

@Composable
fun ThreatInfoSection(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    content: @Composable () -> Unit
) {

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

                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = Color(0xFF00E5FF)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Text(
                    text = title,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            content()
        }
    }
}

@Composable
fun ThreatTimelineItem(
    log: ThreatLog,
    isLast: Boolean
) {

    Column {

        Row(
            verticalAlignment = Alignment.Top
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                Box(
                    modifier = Modifier
                        .size(16.dp)
                        .clip(CircleShape)
                        .background(
                            if (log.completed)
                                Color(0xFF00E676)
                            else
                                Color.Gray
                        )
                )

                if (!isLast) {

                    Spacer(modifier = Modifier.height(4.dp))

                    Box(
                        modifier = Modifier
                            .width(2.dp)
                            .height(55.dp)
                            .background(Color.DarkGray)
                    )
                }
            }

            Spacer(modifier = Modifier.width(14.dp))

            Column {

                Text(
                    text = log.title,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp
                )

                Spacer(modifier = Modifier.height(4.dp))

                Text(
                    text = log.timestamp,
                    color = Color.Gray,
                    fontSize = 12.sp
                )
            }
        }
    }
}

@Composable
fun ActionButtonsSection() {

    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        Button(
            onClick = { },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(18.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF00E5FF),
                contentColor = Color.Black
            )
        ) {

            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null
            )

            Spacer(modifier = Modifier.width(10.dp))

            Text(
                text = "Run Deep Protection Scan",
                fontWeight = FontWeight.Bold
            )
        }

        OutlinedButton(
            onClick = { },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(18.dp),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = Color(0xFFFF5252)
            )
        ) {

            Icon(
                imageVector = Icons.Default.Delete,
                contentDescription = null
            )

            Spacer(modifier = Modifier.width(10.dp))

            Text(
                text = "Remove Threat",
                fontWeight = FontWeight.Bold
            )
        }
    }
}
