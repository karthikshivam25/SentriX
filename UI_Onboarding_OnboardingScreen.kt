package com.sentrix.ui.onboarding

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Analytics
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun OnboardingScreen(
    onGetStartedClick: () -> Unit = {}
) {

    val onboardingPages = remember {

        listOf(

            OnboardingPage(
                title = "Realtime Threat Protection",
                description = "Monitor malware, phishing attempts, suspicious applications and harmful activity instantly.",
                icon = Icons.Rounded.Security,
                gradient = listOf(
                    Color(0xFF00C6FF),
                    Color(0xFF0072FF)
                )
            ),

            OnboardingPage(
                title = "Advanced Privacy Defense",
                description = "Track app permissions, sensor access, clipboard monitoring and hidden background activity.",
                icon = Icons.Rounded.VerifiedUser,
                gradient = listOf(
                    Color(0xFF7C4DFF),
                    Color(0xFF651FFF)
                )
            ),

            OnboardingPage(
                title = "AI Security Analytics",
                description = "Visualize threat trends, device health and protection performance through smart analytics.",
                icon = Icons.Rounded.Analytics,
                gradient = listOf(
                    Color(0xFF00E676),
                    Color(0xFF00C853)
                )
            )
        )
    }

    val pagerState = rememberPagerState(
        pageCount = {
            onboardingPages.size
        }
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF081120),
                        Color(0xFF0F172A),
                        Color(0xFF111827)
                    )
                )
            )
            .navigationBarsPadding()
    ) {

        Column(
            modifier = Modifier.fillMaxSize()
        ) {

            HorizontalPager(
                state = pagerState,
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(horizontal = 24.dp)
            ) { page ->

                val onboardingPage = onboardingPages[page]

                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(top = 80.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {

                    Box(
                        modifier = Modifier
                            .size(190.dp)
                            .clip(RoundedCornerShape(42.dp))
                            .background(
                                brush = Brush.linearGradient(
                                    colors = onboardingPage.gradient
                                )
                            ),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = onboardingPage.icon,
                            contentDescription = onboardingPage.title,
                            tint = Color.White,
                            modifier = Modifier.size(96.dp)
                        )
                    }

                    Spacer(modifier = Modifier.height(54.dp))

                    Text(
                        text = onboardingPage.title,
                        color = Color.White,
                        fontSize = 30.sp,
                        fontWeight = FontWeight.ExtraBold,
                        textAlign = TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(20.dp))

                    Text(
                        text = onboardingPage.description,
                        color = Color(0xFFB0BAC8),
                        fontSize = 16.sp,
                        lineHeight = 28.sp,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 12.dp)
                    )
                }
            }

            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(
                        start = 28.dp,
                        end = 28.dp,
                        bottom = 36.dp
                    ),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {

                // Indicators
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    repeat(onboardingPages.size) { index ->

                        val isSelected =
                            pagerState.currentPage == index

                        AnimatedVisibility(
                            visible = true,
                            enter = fadeIn(),
                            exit = fadeOut()
                        ) {

                            Box(
                                modifier = Modifier
                                    .size(
                                        width = if (isSelected) {
                                            32.dp
                                        } else {
                                            10.dp
                                        },
                                        height = 10.dp
                                    )
                                    .clip(CircleShape)
                                    .background(
                                        if (isSelected) {
                                            Color(0xFF00C6FF)
                                        } else {
                                            Color(0x33FFFFFF)
                                        }
                                    )
                            )
                        }
                    }
                }

                Spacer(modifier = Modifier.height(34.dp))

                Button(
                    onClick = onGetStartedClick,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(60.dp),
                    shape = RoundedCornerShape(18.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF00C6FF),
                        contentColor = Color.White
                    )
                ) {

                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {

                        Icon(
                            imageVector = Icons.Rounded.Shield,
                            contentDescription = null,
                            modifier = Modifier.size(22.dp)
                        )

                        Spacer(modifier = Modifier.size(10.dp))

                        Text(
                            text = "Get Started",
                            fontSize = 17.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(14.dp))

                Text(
                    text = "Secure your device with AI powered protection",
                    color = Color(0xFF7C8799),
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

data class OnboardingPage(
    val title: String,
    val description: String,
    val icon: ImageVector,
    val gradient: List<Color>
)
