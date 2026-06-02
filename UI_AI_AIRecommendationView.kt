package com.sentrix.ui.ai

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowForward
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.PriorityHigh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class AIRecommendation(
    val id: Int,
    val title: String,
    val description: String,
    val priority: AIRecommendationPriority,
    val category: String,
    val completed: Boolean
)

enum class AIRecommendationPriority {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

@Composable
fun AIRecommendationView(

    recommendations: List<AIRecommendation>,
    modifier: Modifier = Modifier,
    onRecommendationClick: (AIRecommendation) -> Unit = {}
) {

    Column(
        modifier = modifier.fillMaxWidth()
    ) {

        Row(
            verticalAlignment = Alignment.CenterVertically
        ) {

            Icon(
                imageVector = Icons.Default.AutoAwesome,
                contentDescription = null,
                tint = Color(0xFF00E5FF)
            )

            Spacer(modifier = Modifier.width(10.dp))

            Text(
                text = "AI Security Recommendations",
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )
        }

        Spacer(modifier = Modifier.height(18.dp))

        LazyColumn(
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {

            items(recommendations) { recommendation ->

                AIRecommendationCard(
                    recommendation = recommendation,
                    onClick = {
                        onRecommendationClick(recommendation)
                    }
                )
            }
        }
    }
}

@Composable
fun AIRecommendationCard(

    recommendation: AIRecommendation,
    onClick: () -> Unit
) {

    val priorityColor by animateColorAsState(
        targetValue = when (recommendation.priority) {
            AIRecommendationPriority.LOW -> Color(0xFF00E676)
            AIRecommendationPriority.MEDIUM -> Color(0xFFFFC400)
            AIRecommendationPriority.HIGH -> Color(0xFFFF9100)
            AIRecommendationPriority.CRITICAL -> Color(0xFFFF1744)
        },
        label = "priority_color"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                onClick()
            },
        shape = RoundedCornerShape(26.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 5.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF182235),
                            Color(0xFF101827)
                        )
                    )
                )
                .padding(18.dp)
        ) {

            Column {

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(52.dp)
                            .clip(CircleShape)
                            .background(
                                priorityColor.copy(alpha = 0.15f)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = if (recommendation.completed) {
                                Icons.Default.CheckCircle
                            } else {
                                Icons.Default.Security
                            },
                            contentDescription = null,
                            tint = priorityColor,
                            modifier = Modifier.size(28.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = recommendation.title,
                            color = Color.White,
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            PriorityBadge(
                                priority = recommendation.priority,
                                color = priorityColor
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            CategoryBadge(
                                category = recommendation.category
                            )
                        }
                    }

                    Icon(
                        imageVector = Icons.Default.ArrowForward,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF)
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Text(
                    text = recommendation.description,
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp,
                    maxLines = 4,
                    overflow = TextOverflow.Ellipsis
                )

                Spacer(modifier = Modifier.height(18.dp))

                Surface(
                    shape = RoundedCornerShape(18.dp),
                    color = if (recommendation.completed) {
                        Color(0x2200E676)
                    } else {
                        priorityColor.copy(alpha = 0.12f)
                    }
                ) {

                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(
                                horizontal = 16.dp,
                                vertical = 12.dp
                            ),
                        verticalAlignment = Alignment.CenterVertically
                    ) {

                        Icon(
                            imageVector = if (recommendation.completed) {
                                Icons.Default.CheckCircle
                            } else {
                                Icons.Default.PriorityHigh
                            },
                            contentDescription = null,
                            tint = if (recommendation.completed) {
                                Color(0xFF00E676)
                            } else {
                                priorityColor
                            },
                            modifier = Modifier.size(18.dp)
                        )

                        Spacer(modifier = Modifier.width(10.dp))

                        Text(
                            text = if (recommendation.completed) {
                                "Recommendation implemented successfully."
                            } else {
                                "AI recommends immediate attention."
                            },
                            color = Color.White,
                            fontSize = 13.sp,
                            lineHeight = 20.sp
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun PriorityBadge(

    priority: AIRecommendationPriority,
    color: Color
) {

    Surface(
        shape = RoundedCornerShape(50),
        color = color.copy(alpha = 0.15f)
    ) {

        Text(
            text = priority.name,
            modifier = Modifier.padding(
                horizontal = 10.dp,
                vertical = 5.dp
            ),
            color = color,
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun CategoryBadge(

    category: String
) {

    Surface(
        shape = RoundedCornerShape(50),
        color = Color(0x2215E5FF)
    ) {

        Text(
            text = category,
            modifier = Modifier.padding(
                horizontal = 10.dp,
                vertical = 5.dp
            ),
            color = Color(0xFF00E5FF),
            fontSize = 10.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun AIRecommendationPreviewData(): List<AIRecommendation> {

    return listOf(

        AIRecommendation(
            id = 1,
            title = "Enable Advanced Phishing Protection",
            description = "AI analysis detected increased phishing attempts targeting credential inputs. Enabling advanced protection will strengthen URL and email verification.",
            priority = AIRecommendationPriority.CRITICAL,
            category = "Phishing",
            completed = false
        ),

        AIRecommendation(
            id = 2,
            title = "Run Deep Behavioral Scan",
            description = "Suspicious runtime activities were identified from background processes. A deep behavioral scan is recommended for enhanced analysis.",
            priority = AIRecommendationPriority.HIGH,
            category = "Malware",
            completed = false
        ),

        AIRecommendation(
            id = 3,
            title = "Secure Public Wi-Fi Connections",
            description = "AI detected repeated connections to unsecured public networks. VPN auto-protection has been successfully enabled.",
            priority = AIRecommendationPriority.MEDIUM,
            category = "Network",
            completed = true
        )
    )
}
