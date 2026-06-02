package com.sentrix.ui.ai

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class AIShieldState {
    ACTIVE,
    SCANNING,
    INACTIVE
}

data class AIThreatInsight(
    val title: String,
    val description: String,
    val severity: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AIShieldScreen() {

    var shieldState by remember {
        mutableStateOf(AIShieldState.ACTIVE)
    }

    val insights = remember {
        listOf(
            AIThreatInsight(
                title = "Behavioral Threat Detection",
                description = "AI engine detected unusual background execution patterns from an unknown application.",
                severity = "HIGH"
            ),
            AIThreatInsight(
                title = "Phishing URL Prevention",
                description = "Suspicious credential harvesting URL was blocked before access.",
                severity = "CRITICAL"
            ),
            AIThreatInsight(
                title = "Real-Time App Monitoring",
                description = "Continuous monitoring enabled for application privilege escalation attempts.",
                severity = "MEDIUM"
            )
        )
    }

    val statusColor = when (shieldState) {
        AIShieldState.ACTIVE -> Color(0xFF00E676)
        AIShieldState.SCANNING -> Color(0xFFFFC400)
        AIShieldState.INACTIVE -> Color(0xFFFF5252)
    }

    val infiniteTransition = rememberInfiniteTransition(
        label = "ai_shield_animation"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 1400,
                easing = EaseInOut
            ),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_alpha"
    )

    val rotationAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(
                durationMillis = 5000,
                easing = LinearEasing
            )
        ),
        label = "rotation_angle"
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "AI Shield",
                        fontWeight = FontWeight.Bold
                    )
                },
                actions = {

                    IconButton(onClick = { }) {
                        Icon(
                            imageVector = Icons.Default.Tune,
                            contentDescription = null
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
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {

            item {
                Spacer(modifier = Modifier.height(6.dp))
            }

            item {

                AIShieldHeroCard(
                    state = shieldState,
                    statusColor = statusColor,
                    pulseAlpha = pulseAlpha,
                    rotationAngle = rotationAngle,
                    onToggleShield = {

                        shieldState = when (shieldState) {
                            AIShieldState.ACTIVE -> AIShieldState.INACTIVE
                            AIShieldState.INACTIVE -> AIShieldState.SCANNING
                            AIShieldState.SCANNING -> AIShieldState.ACTIVE
                        }
                    }
                )
            }

            item {

                AIProtectionStats()
            }

            item {

                Text(
                    text = "AI Threat Intelligence",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            items(insights.size) { index ->

                AIThreatInsightCard(
                    insight = insights[index]
                )
            }

            item {
                Spacer(modifier = Modifier.height(28.dp))
            }
        }
    }
}

@Composable
fun AIShieldHeroCard(

    state: AIShieldState,
    statusColor: Color,
    pulseAlpha: Float,
    rotationAngle: Float,
    onToggleShield: () -> Unit
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(32.dp),
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
                .padding(vertical = 30.dp),
            contentAlignment = Alignment.Center
        ) {

            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                Box(
                    modifier = Modifier.size(250.dp),
                    contentAlignment = Alignment.Center
                ) {

                    Box(
                        modifier = Modifier
                            .size(170.dp)
                            .clip(CircleShape)
                            .background(
                                statusColor.copy(alpha = pulseAlpha * 0.18f)
                            )
                    )

                    Canvas(
                        modifier = Modifier.size(220.dp)
                    ) {

                        drawArc(
                            color = Color(0xFF2A3550),
                            startAngle = 0f,
                            sweepAngle = 360f,
                            useCenter = false,
                            style = Stroke(
                                width = 10.dp.toPx(),
                                cap = StrokeCap.Round
                            )
                        )

                        drawArc(
                            brush = Brush.sweepGradient(
                                colors = listOf(
                                    statusColor,
                                    Color(0xFF00E5FF),
                                    statusColor
                                )
                            ),
                            startAngle = rotationAngle,
                            sweepAngle = 120f,
                            useCenter = false,
                            style = Stroke(
                                width = 10.dp.toPx(),
                                cap = StrokeCap.Round
                            )
                        )
                    }

                    FilledIconButton(
                        onClick = onToggleShield,
                        modifier = Modifier.size(100.dp),
                        colors = IconButtonDefaults.filledIconButtonColors(
                            containerColor = statusColor
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = Color.Black,
                            modifier = Modifier.size(44.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                Text(
                    text = when (state) {
                        AIShieldState.ACTIVE -> "AI Shield Active"
                        AIShieldState.SCANNING -> "AI Deep Scanning"
                        AIShieldState.INACTIVE -> "AI Shield Disabled"
                    },
                    color = Color.White,
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = when (state) {
                        AIShieldState.ACTIVE ->
                            "Real-time behavioral protection is monitoring your device."

                        AIShieldState.SCANNING ->
                            "Advanced AI models are analyzing suspicious activities."

                        AIShieldState.INACTIVE ->
                            "Your device is currently vulnerable to advanced threats."
                    },
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp,
                    modifier = Modifier.padding(horizontal = 30.dp)
                )

                Spacer(modifier = Modifier.height(22.dp))

                Surface(
                    shape = RoundedCornerShape(50),
                    color = statusColor.copy(alpha = 0.15f)
                ) {

                    Row(
                        modifier = Modifier.padding(
                            horizontal = 18.dp,
                            vertical = 10.dp
                        ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Box(
                            modifier = Modifier
                                .size(10.dp)
                                .clip(CircleShape)
                                .background(statusColor)
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(
                            text = when (state) {
                                AIShieldState.ACTIVE -> "PROTECTED"
                                AIShieldState.SCANNING -> "SCANNING"
                                AIShieldState.INACTIVE -> "UNPROTECTED"
                            },
                            color = statusColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AIProtectionStats() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(14.dp)
    ) {

        AIStatCard(
            modifier = Modifier.weight(1f),
            title = "Threats Blocked",
            value = "128",
            icon = Icons.Default.GppGood,
            valueColor = Color(0xFF00E676)
        )

        AIStatCard(
            modifier = Modifier.weight(1f),
            title = "AI Accuracy",
            value = "99.2%",
            icon = Icons.Default.Psychology,
            valueColor = Color(0xFF00E5FF)
        )
    }
}

@Composable
fun AIStatCard(

    modifier: Modifier = Modifier,
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    valueColor: Color
) {

    Card(
        modifier = modifier,
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF151C2E)
        )
    ) {

        Column(
            modifier = Modifier.padding(18.dp)
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color(0xFF00E5FF)
            )

            Spacer(modifier = Modifier.height(18.dp))

            Text(
                text = title,
                color = Color.Gray,
                fontSize = 12.sp
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = value,
                color = valueColor,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}

@Composable
fun AIThreatInsightCard(

    insight: AIThreatInsight
) {

    val severityColor = when (insight.severity) {
        "LOW" -> Color(0xFF00E676)
        "MEDIUM" -> Color(0xFFFFC400)
        "HIGH" -> Color(0xFFFF9100)
        else -> Color(0xFFFF1744)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF151C2E)
        )
    ) {

        Column(
            modifier = Modifier.padding(18.dp)
        ) {

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {

                Icon(
                    imageVector = Icons.Default.AutoAwesome,
                    contentDescription = null,
                    tint = Color(0xFF00E5FF)
                )

                Spacer(modifier = Modifier.width(10.dp))

                Text(
                    text = insight.title,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 16.sp,
                    modifier = Modifier.weight(1f)
                )

                Surface(
                    shape = RoundedCornerShape(50),
                    color = severityColor.copy(alpha = 0.15f)
                ) {

                    Text(
                        text = insight.severity,
                        modifier = Modifier.padding(
                            horizontal = 12.dp,
                            vertical = 6.dp
                        ),
                        color = severityColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = insight.description,
                color = Color.LightGray,
                fontSize = 14.sp,
                lineHeight = 22.sp
            )

            Spacer(modifier = Modifier.height(16.dp))

            AnimatedVisibility(
                visible = true
            ) {

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Icon(
                        imageVector = Icons.Default.Bolt,
                        contentDescription = null,
                        tint = Color(0xFF00E676),
                        modifier = Modifier.size(18.dp)
                    )

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = "AI mitigation response completed",
                        color = Color(0xFF00E676),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}
