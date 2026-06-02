package com.sentrix.ui.analytics

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.GridView
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ThreatHeatmap(
    modifier: Modifier = Modifier,
    heatmapData: List<List<Float>> = listOf(
        listOf(0.1f, 0.4f, 0.7f, 0.2f, 0.9f, 0.5f, 0.3f),
        listOf(0.6f, 0.2f, 0.8f, 0.3f, 0.4f, 0.7f, 0.1f),
        listOf(0.5f, 0.9f, 0.3f, 0.8f, 0.2f, 0.6f, 0.4f),
        listOf(0.2f, 0.7f, 0.5f, 0.9f, 0.1f, 0.8f, 0.3f)
    ),
    rowLabels: List<String> = listOf(
        "Apps",
        "Network",
        "Storage",
        "Permissions"
    ),
    columnLabels: List<String> = listOf(
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat",
        "Sun"
    )
) {

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF141B26)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Column(
            modifier = Modifier.padding(22.dp)
        ) {

            // Header
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(
                            brush = Brush.linearGradient(
                                colors = listOf(
                                    Color(0xFFFF5252),
                                    Color(0xFFFF1744)
                                )
                            ),
                            shape = RoundedCornerShape(18.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Rounded.GridView,
                        contentDescription = "Threat Heatmap",
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }

                Spacer(modifier = Modifier.size(14.dp))

                Column {

                    Text(
                        text = "Threat Heatmap",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Threat intensity across security modules",
                        color = Color(0xFF9CA3AF),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Column Labels
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {

                Spacer(modifier = Modifier.size(56.dp))

                columnLabels.forEach { label ->

                    Text(
                        text = label,
                        color = Color(0xFF9CA3AF),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Heatmap Rows
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {

                items(heatmapData.size) { rowIndex ->

                    HeatmapRow(
                        label = rowLabels[rowIndex],
                        values = heatmapData[rowIndex]
                    )
                }
            }

            Spacer(modifier = Modifier.height(26.dp))

            // Footer Legend
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {

                ThreatLegend(
                    color = Color(0x3300E676),
                    title = "Low"
                )

                ThreatLegend(
                    color = Color(0x66FFC107),
                    title = "Medium"
                )

                ThreatLegend(
                    color = Color(0xAAFF5252),
                    title = "High"
                )
            }
        }
    }
}

@Composable
fun HeatmapRow(
    label: String,
    values: List<Float>
) {

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        Text(
            text = label,
            color = Color.White,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f)
        )

        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {

            values.forEach { value ->

                HeatmapCell(
                    intensity = value
                )
            }
        }
    }
}

@Composable
fun HeatmapCell(
    intensity: Float
) {

    val animatedAlpha by animateFloatAsState(
        targetValue = intensity.coerceIn(0f, 1f),
        label = "HeatmapAlpha"
    )

    Box(
        modifier = Modifier
            .size(28.dp)
            .alpha(animatedAlpha)
            .background(
                color = getThreatHeatColor(intensity),
                shape = RoundedCornerShape(8.dp)
            )
    )
}

@Composable
fun ThreatLegend(
    color: Color,
    title: String
) {

    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(14.dp)
                .background(
                    color = color,
                    shape = RoundedCornerShape(4.dp)
                )
        )

        Spacer(modifier = Modifier.size(8.dp))

        Text(
            text = title,
            color = Color(0xFFD1D5DB),
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

fun getThreatHeatColor(
    intensity: Float
): Color {

    return when {
        intensity < 0.30f -> Color(0x3300E676)
        intensity < 0.60f -> Color(0x66FFC107)
        else -> Color(0xAAFF5252)
    }
}
