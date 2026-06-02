package com.sentrix.ui.ai

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class AIChatMessage(
    val id: Int,
    val message: String,
    val isUser: Boolean,
    val timestamp: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AIChatAssistant() {

    var inputText by remember {
        mutableStateOf("")
    }

    val chatMessages = remember {
        mutableStateListOf(
            AIChatMessage(
                id = 1,
                message = "Hello! I am your SentriX AI Security Assistant. How can I help protect your device today?",
                isUser = false,
                timestamp = "10:21 AM"
            ),
            AIChatMessage(
                id = 2,
                message = "Analyze recent phishing threats detected on my device.",
                isUser = true,
                timestamp = "10:22 AM"
            ),
            AIChatMessage(
                id = 3,
                message = "I detected 3 suspicious phishing attempts in the last 24 hours. All malicious URLs were blocked before interaction.",
                isUser = false,
                timestamp = "10:22 AM"
            )
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
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
                            text = "AI Security Assistant",
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            )
        },
        containerColor = Color(0xFF0B1020),
        bottomBar = {

            AIChatInputBar(
                inputText = inputText,
                onTextChange = {
                    inputText = it
                },
                onSendClick = {

                    if (inputText.isNotBlank()) {

                        chatMessages.add(
                            AIChatMessage(
                                id = chatMessages.size + 1,
                                message = inputText,
                                isUser = true,
                                timestamp = "Now"
                            )
                        )

                        chatMessages.add(
                            AIChatMessage(
                                id = chatMessages.size + 2,
                                message = "AI Shield is analyzing your request securely.",
                                isUser = false,
                                timestamp = "Now"
                            )
                        )

                        inputText = ""
                    }
                }
            )
        }
    ) { paddingValues ->

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {

            AIChatHeader()

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
                contentPadding = PaddingValues(vertical = 18.dp)
            ) {

                items(chatMessages) { message ->

                    AIChatBubble(
                        message = message
                    )
                }
            }
        }
    }
}

@Composable
fun AIChatHeader() {

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = 16.dp,
                vertical = 14.dp
            ),
        shape = RoundedCornerShape(26.dp),
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

            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth()
            ) {

                Box(
                    modifier = Modifier
                        .size(72.dp)
                        .clip(CircleShape)
                        .background(Color(0x2200E5FF)),
                    contentAlignment = Alignment.Center
                ) {

                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = null,
                        tint = Color(0xFF00E5FF),
                        modifier = Modifier.size(38.dp)
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                Text(
                    text = "AI-Powered Threat Intelligence",
                    color = Color.White,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.Bold,
                    textAlign = TextAlign.Center
                )

                Spacer(modifier = Modifier.height(10.dp))

                Text(
                    text = "Ask security questions, analyze threats, and receive real-time protection insights powered by SentriX AI.",
                    color = Color.LightGray,
                    fontSize = 14.sp,
                    lineHeight = 22.sp,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

@Composable
fun AIChatBubble(

    message: AIChatMessage
) {

    val bubbleColor = if (message.isUser) {
        Color(0xFF00E5FF)
    } else {
        Color(0xFF151C2E)
    }

    val textColor = if (message.isUser) {
        Color.Black
    } else {
        Color.White
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (message.isUser) {
            Arrangement.End
        } else {
            Arrangement.Start
        }
    ) {

        Column(
            horizontalAlignment = if (message.isUser) {
                Alignment.End
            } else {
                Alignment.Start
            }
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
                        bottomStart = if (message.isUser) 24.dp else 6.dp,
                        bottomEnd = if (message.isUser) 6.dp else 24.dp
                    ),
                    color = bubbleColor,
                    tonalElevation = 4.dp
                ) {

                    Text(
                        text = message.message,
                        modifier = Modifier.padding(16.dp),
                        color = textColor,
                        fontSize = 14.sp,
                        lineHeight = 22.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = message.timestamp,
                color = Color.Gray,
                fontSize = 11.sp
            )
        }
    }
}

@Composable
fun AIChatInputBar(

    inputText: String,
    onTextChange: (String) -> Unit,
    onSendClick: () -> Unit
) {

    Surface(
        color = Color(0xFF101728),
        tonalElevation = 8.dp
    ) {

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(
                    horizontal = 14.dp,
                    vertical = 12.dp
                ),
            verticalAlignment = Alignment.CenterVertically
        ) {

            OutlinedTextField(
                value = inputText,
                onValueChange = onTextChange,
                modifier = Modifier.weight(1f),
                placeholder = {
                    Text(
                        text = "Ask AI Security Assistant...",
                        color = Color.Gray
                    )
                },
                shape = RoundedCornerShape(22.dp),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = Color(0xFF151C2E),
                    unfocusedContainerColor = Color(0xFF151C2E),
                    focusedBorderColor = Color(0xFF00E5FF),
                    unfocusedBorderColor = Color.Transparent,
                    focusedTextColor = Color.White,
                    unfocusedTextColor = Color.White,
                    cursorColor = Color(0xFF00E5FF)
                ),
                maxLines = 4
            )

            Spacer(modifier = Modifier.width(12.dp))

            Column(
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {

                FilledIconButton(
                    onClick = { },
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = Color(0xFF1E293B)
                    )
                ) {

                    Icon(
                        imageVector = Icons.Default.Mic,
                        contentDescription = null,
                        tint = Color.White
                    )
                }

                FilledIconButton(
                    onClick = onSendClick,
                    colors = IconButtonDefaults.filledIconButtonColors(
                        containerColor = Color(0xFF00E5FF)
                    )
                ) {

                    Icon(
                        imageVector = Icons.Default.Send,
                        contentDescription = null,
                        tint = Color.Black
                    )
                }
            }
        }
    }
}
