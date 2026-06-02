package com.sentrix.ui.visual

import androidx.compose.foundation.Canvas
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ThreatGraphCard() {

    val graphPoints = listOf(
        180f,
        120f,
        150f,
        90f,
        110f,
        70f,
        95f
    )

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .background(
                color = Color(0xFF0F172A),
                shape = RoundedCornerShape(24.dp)
            )
            .padding(20.dp)
    ) {

        Column {

            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {

                Box(
                    modifier = Modifier
                        .size(46.dp)
                        .background(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Security,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Threat Detection",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Weekly security analytics",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            ThreatLineChart(
                values = graphPoints
            )

            Spacer(modifier = Modifier.height(22.dp))

            ThreatLegendRow()
        }
    }
}

@Composable
fun ThreatLineChart(
    values: List<Float>
) {

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(220.dp)
    ) {

        val spacing = size.width / (values.size - 1)

        val maxValue = values.maxOrNull() ?: 0f
        val minValue = values.minOrNull() ?: 0f

        val graphHeight = size.height

        val path = Path()

        values.forEachIndexed { index, value ->

            val x = spacing * index

            val normalizedValue =
                (value - minValue) / (maxValue - minValue)

            val y = graphHeight - (normalizedValue * graphHeight)

            if (index == 0) {
                path.moveTo(x, y)
            } else {
                path.lineTo(x, y)
            }
        }

        drawPath(
            path = path,
            brush = Brush.horizontalGradient(
                colors = listOf(
                    Color(0xFF2563EB),
                    Color(0xFF38BDF8)
                )
            ),
            style = Stroke(
                width = 8f,
                cap = StrokeCap.Round
            )
        )

        values.forEachIndexed { index, value ->

            val x = spacing * index

            val normalizedValue =
                (value - minValue) / (maxValue - minValue)

            val y = graphHeight - (normalizedValue * graphHeight)

            drawCircle(
                color = Color(0xFF7DD3FC),
                radius = 10f,
                center = Offset(x, y)
            )

            drawCircle(
                color = Color(0xFF0F172A),
                radius = 5f,
                center = Offset(x, y)
            )
        }
    }
}

@Composable
fun ThreatLegendRow() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        ThreatLegendItem(
            color = Color(0xFF38BDF8),
            label = "Threat Activity"
        )

        ThreatLegendItem(
            color = Color(0xFF22C55E),
            label = "Protection Active"
        )
    }
}

@Composable
fun ThreatLegendItem(
    color: Color,
    label: String
) {

    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {

        Box(
            modifier = Modifier
                .size(12.dp)
                .background(
                    color = color,
                    shape = RoundedCornerShape(50)
                )
        )

        Spacer(modifier = Modifier.size(8.dp))

        Text(
            text = label,
            color = Color(0xFFCBD5E1),
            fontSize = 13.sp
        )
    }
}
