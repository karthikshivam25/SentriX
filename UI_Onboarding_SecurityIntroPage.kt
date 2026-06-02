package com.sentrix.ui.onboarding

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowForward
import androidx.compose.material.icons.rounded.GppGood
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.NetworkCheck
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

@Composable
fun SecurityIntroPage(
    onContinueClick: () -> Unit = {}
) {

    var contentVisible by remember {
        mutableStateOf(false)
    }

    LaunchedEffect(Unit) {

        delay(300)

        contentVisible = true
    }

    val animatedScale by animateFloatAsState(
        targetValue = if (contentVisible) 1f else 0.82f,
        animationSpec = tween(
            durationMillis = 900,
            easing = FastOutSlowInEasing
        ),
        label = "SecurityIntroScale"
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF07111F),
                        Color(0xFF0F172A),
                        Color(0xFF131C2B)
                    )
                )
            )
            .navigationBarsPadding()
    ) {

        // Background Glow
        Box(
            modifier = Modifier
                .size(320.dp)
                .align(Alignment.TopCenter)
                .alpha(0.18f)
                .background(
                    color = Color(0xFF00E676),
                    shape = CircleShape
                )
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {

            Spacer(modifier = Modifier.height(60.dp))

            AnimatedVisibility(
                visible = contentVisible,
                enter = fadeIn(
                    animationSpec = tween(900)
                ) + slideInVertically(
                    initialOffsetY = { it / 3 },
                    animationSpec = tween(900)
                )
            ) {

                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {

                    // Main Shield
                    Box(
                        modifier = Modifier
                            .size(170.dp)
                            .scale(animatedScale)
                            .background(
                                brush = Brush.linearGradient(
                                    colors = listOf(
                                        Color(0xFF00E676),
                                        Color(0xFF00C853)
                                    )
                                ),
                                shape = RoundedCornerShape(44.dp)
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Rounded.Security,
                            contentDescription = "Security Shield",
                            tint = Color.White,
                            modifier = Modifier.size(88.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(40.dp))

                    Text(
                        text = "Advanced Cyber Protection",
                        color = Color.White,
                        fontSize = 32.sp,
                        fontWeight = FontWeight.ExtraBold,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(18.dp))

                    Text(
                        text = "SentriX continuously protects your device against malware, phishing, privacy leaks and suspicious activity in realtime.",
                        color = Color(0xFFB0BAC8),
                        fontSize = 16.sp,
                        lineHeight = 28.sp,
                        textAlign = TextAlign.Center
                    )
                }
            }

            Spacer(modifier = Modifier.height(40.dp))

            Column(
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {

                SecurityFeatureCard(
                    icon = Icons.Rounded.GppGood,
                    title = "Realtime Threat Detection",
                    description = "Detect malicious behavior instantly using AI based analysis.",
                    accentColor = Color(0xFF00E676)
                )

                SecurityFeatureCard(
                    icon = Icons.Rounded.Lock,
                    title = "Privacy Monitoring",
                    description = "Track permissions, sensors and sensitive data access.",
                    accentColor = Color(0xFF00C6FF)
                )

                SecurityFeatureCard(
                    icon = Icons.Rounded.NetworkCheck,
                    title = "Network Protection",
                    description = "Monitor unsafe connections and suspicious network activity.",
                    accentColor = Color(0xFFFFC107)
                )

                SecurityFeatureCard(
                    icon = Icons.Rounded.VerifiedUser,
                    title = "Secure App Analysis",
                    description = "Analyze installed apps and APK files for hidden threats.",
                    accentColor = Color(0xFF7C4DFF)
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = onContinueClick,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(60.dp),
                shape = RoundedCornerShape(18.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color(0xFF00E676),
                    contentColor = Color.White
                )
            ) {

                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Text(
                        text = "Continue",
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Bold
                    )

                    Spacer(modifier = Modifier.size(10.dp))

                    Icon(
                        imageVector = Icons.Rounded.ArrowForward,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))
        }
    }
}

@Composable
fun SecurityFeatureCard(
    icon: ImageVector,
    title: String,
    description: String,
    accentColor: Color
) {

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF182231)
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 6.dp
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
                    .size(58.dp)
                    .background(
                        color = accentColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(18.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {

                Icon(
                    imageVector = icon,
                    contentDescription = title,
                    tint = accentColor,
                    modifier = Modifier.size(30.dp)
                )
            }

            Spacer(modifier = Modifier.size(16.dp))

            Column {

                Text(
                    text = title,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )

                Spacer(modifier = Modifier.height(6.dp))

                Text(
                    text = description,
                    color = Color(0xFFB0BAC8),
                    fontSize = 13.sp,
                    lineHeight = 20.sp
                )
            }
        }
    }
}
