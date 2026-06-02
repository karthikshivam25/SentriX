package com.sentrix.ui.ai

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

enum class AIMessageSender {
    USER,
    AI
}

data class AIMessageData(
    val id: Int,
    val sender: AIMessageSender,
    val message: String,
    val timestamp: String
)

@Composable
fun AIMessageBubble(

    data: AIMessageData,
    modifier: Modifier = Modifier
) {

    val isUser = data.sender == AIMessageSender.USER

    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = if (isUser) {
            Arrangement.End
        } else {
            Arrangement.Start
        }
    ) {

        if (!isUser) {

            AIAvatar()
            Spacer(modifier = Modifier.width(10.dp))
        }

        Column(
            horizontalAlignment = if (isUser) {
                Alignment.End
            } else {
                Alignment.Start
            },
            modifier = Modifier.widthIn(max = 320.dp)
        ) {

            AnimatedVisibility(
                visible = true,
                enter = fadeIn(),
                exit = fadeOut()
            ) {

                Surface(
                    shape = RoundedCornerShape(
                        topStart = 24.dp,
                        topEnd = 24.dp,
                        bottomStart = if (isUser) 24.dp else 8.dp,
                        bottomEnd = if (isUser) 8.dp else 24.dp
                    ),
                    tonalElevation = 5.dp,
                    color = Color.Transparent
                ) {

                    Box(
                        modifier = Modifier.background(
                            brush = if (isUser) {
                                Brush.horizontalGradient(
                                    colors = listOf(
                                        Color(0xFF00E5FF),
                                        Color(0xFF00B8D4)
                                    )
                                )
                            } else {
                                Brush.verticalGradient(
                                    colors = listOf(
                                        Color(0xFF1A1F35),
                                        Color(0xFF151C2E)
                                    )
                                )
                            }
                        )
                    ) {

                        Text(
                            text = data.message,
                            modifier = Modifier.padding(
                                horizontal = 18.dp,
                                vertical = 14.dp
                            ),
                            color = if (isUser) {
                                Color.Black
                            } else {
                                Color.White
                            },
                            fontSize = 14.sp,
                            lineHeight = 22.sp,
                            textAlign = TextAlign.Start
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = data.timestamp,
                color = Color.Gray,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium
            )
        }

        if (isUser) {

            Spacer(modifier = Modifier.width(10.dp))
            UserAvatar()
        }
    }
}

@Composable
fun AIAvatar() {

    Surface(
        shape = RoundedCornerShape(18.dp),
        color = Color(0x2200E5FF)
    ) {

        Box(
            modifier = Modifier
                .size(42.dp),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = Icons.Default.AutoAwesome,
                contentDescription = null,
                tint = Color(0xFF00E5FF),
                modifier = Modifier.size(22.dp)
            )
        }
    }
}

@Composable
fun UserAvatar() {

    Surface(
        shape = RoundedCornerShape(18.dp),
        color = Color(0x2215E676)
    ) {

        Box(
            modifier = Modifier
                .size(42.dp),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = Icons.Default.Person,
                contentDescription = null,
                tint = Color(0xFF00E676),
                modifier = Modifier.size(22.dp)
            )
        }
    }
}

@Composable
fun AIMessagePreviewData(): List<AIMessageData> {

    return listOf(

        AIMessageData(
            id = 1,
            sender = AIMessageSender.AI,
            message = "Hello! I’m SentriX AI Security Assistant. How can I help secure your device today?",
            timestamp = "10:21 AM"
        ),

        AIMessageData(
            id = 2,
            sender = AIMessageSender.USER,
            message = "Analyze recent phishing activity detected on my device.",
            timestamp = "10:22 AM"
        ),

        AIMessageData(
            id = 3,
            sender = AIMessageSender.AI,
            message = "Three phishing attempts were detected and blocked successfully. No credential compromise was identified.",
            timestamp = "10:22 AM"
        )
    )
}
