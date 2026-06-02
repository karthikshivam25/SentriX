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
import androidx.compose.material.icons.filled.NetworkCheck
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
fun NetworkTrafficGraphCard() {

    val uploadTraffic = listOf(
        40f,
        65f,
        52f,
        88f,
        60f,
        92f,
        70f
    )

    val downloadTraffic = listOf(
        25f,
        48f,
        35f,
        72f,
        50f,
        80f,
        58f
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
                        .size(48.dp)
                        .background(
                            color = Color(0xFF1E293B),
                            shape = RoundedCornerShape(14.dp)
                        ),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.NetworkCheck,
                        contentDescription = null,
                        tint = Color(0xFF38BDF8)
                    )
                }

                Column(
                    modifier = Modifier.padding(start = 14.dp)
                ) {

                    Text(
                        text = "Network Traffic",
                        color = Color.White,
                        fontWeight = FontWeight.Bold,
                        fontSize = 20.sp
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Live upload & download activity",
                        color = Color(0xFF94A3B8),
                        fontSize = 13.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))

            TrafficGraph(
                uploadValues = uploadTraffic,
                downloadValues = downloadTraffic
            )

            Spacer(modifier = Modifier.height(24.dp))

            TrafficLegendSection()
        }
    }
}

@Composable
fun TrafficGraph(
    uploadValues: List<Float>,
    downloadValues: List<Float>
) {

    Canvas(
        modifier = Modifier
            .fillMaxWidth()
            .height(240.dp)
    ) {

        val spacing =
            size.width / (uploadValues.size - 1)

        val maxValue =
            (uploadValues + downloadValues).maxOrNull() ?: 100f

        fun createGraphPath(values: List<Float>): Path {

            val path = Path()

            values.forEachIndexed { index, value ->

                val x = spacing * index

                val normalizedValue =
                    value / maxValue

                val y =
                    size.height - (normalizedValue * size.height)

                if (index == 0) {
                    path.moveTo(x, y)
                } else {
                    path.lineTo(x, y)
                }
            }

            return path
        }

        val uploadPath = createGraphPath(uploadValues)
        val downloadPath = createGraphPath(downloadValues)

        drawPath(
            path = uploadPath,
            brush = Brush.horizontalGradient(
                colors = listOf(
                    Color(0xFF38BDF8),
                    Color(0xFF2563EB)
                )
            ),
            style = Stroke(
                width = 7f,
                cap = StrokeCap.Round
            )
        )

        drawPath(
            path = downloadPath,
            brush = Brush.horizontalGradient(
                colors = listOf(
                    Color(0xFF22C55E),
                    Color(0xFF4ADE80)
                )
            ),
            style = Stroke(
                width = 7f,
                cap = StrokeCap.Round
            )
        )

        uploadValues.forEachIndexed { index, value ->

            val x = spacing * index

            val y =
                size.height - ((value / maxValue) * size.height)

            drawCircle(
                color = Color(0xFF7DD3FC),
                radius = 8f,
                center = Offset(x, y)
            )
        }

        downloadValues.forEachIndexed { index, value ->

            val x = spacing * index

            val y =
                size.height - ((value / maxValue) * size.height)

            drawCircle(
                color = Color(0xFF86EFAC),
                radius = 8f,
                center = Offset(x, y)
            )
        }
    }
}

@Composable
fun TrafficLegendSection() {

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        TrafficLegendItem(
            color = Color(0xFF38BDF8),
            label = "Upload"
        )

        TrafficLegendItem(
            color = Color(0xFF22C55E),
            label = "Download"
        )

        TrafficLegendItem(
            color = Color(0xFFFACC15),
            label = "Protected"
        )
    }
}

@Composable
fun TrafficLegendItem(
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
