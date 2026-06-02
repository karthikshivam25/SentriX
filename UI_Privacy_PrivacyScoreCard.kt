package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class PrivacyScoreModel(
    val privacyScore: Int,
    val protectedApps: Int,
    val blockedTrackers: Int,
    val activeThreats: Int,
    val securityStatus: String
)

@Composable
fun PrivacyScoreCard(
    privacy: PrivacyScoreModel,
    modifier: Modifier = Modifier
) {

    val scoreColor = when {
        privacy.privacyScore >= 85 -> Color(0xFF00E676)
        privacy.privacyScore >= 60 -> Color(0xFFFFC400)
        else -> Color(0xFFFF5252)
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 12.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF0F172A),
                            Color(0xFF172554),
                            Color(0xFF111827)
                        )
                    )
                )
                .padding(24.dp)
        ) {

            Column(
                modifier = Modifier.fillMaxWidth()
            ) {

                // Header
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {

                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .clip(CircleShape)
                            .background(scoreColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null,
                            tint = scoreColor,
                            modifier = Modifier.size(34.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = "Privacy Protection Score",
                            color = Color.White,
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = privacy.securityStatus,
                            color = scoreColor,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(28.dp))

                // Score Section
                Row(
                    verticalAlignment = Alignment.Bottom
                ) {

                    Text(
                        text = "${privacy.privacyScore}",
                        color = scoreColor,
                        fontSize = 58.sp,
                        fontWeight = FontWeight.ExtraBold
                    )

                    Spacer(modifier = Modifier.width(6.dp))

                    Text(
                        text = "/100",
                        color = Color(0xFF90A4AE),
                        fontSize = 20.sp,
                        modifier = Modifier.padding(bottom = 10.dp)
                    )
                }

                Spacer(modifier = Modifier.height(18.dp))

                LinearProgressIndicator(
                    progress = { privacy.privacyScore / 100f },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(10.dp)
                        .clip(RoundedCornerShape(50)),
                    color = scoreColor,
                    trackColor = Color(0xFF334155)
                )

                Spacer(modifier = Modifier.height(28.dp))

                // Metrics
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {

                    PrivacyMetricItem(
                        icon = Icons.Default.VerifiedUser,
                        value = "${privacy.protectedApps}",
                        label = "Protected"
                    )

                    PrivacyMetricItem(
                        icon = Icons.Default.Shield,
                        value = "${privacy.blockedTrackers}",
                        label = "Blocked"
                    )

                    PrivacyMetricItem(
                        icon = Icons.Default.Lock,
                        value = "${privacy.activeThreats}",
                        label = "Threats"
                    )
                }

                Spacer(modifier = Modifier.height(26.dp))

                // Footer Message
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color.White.copy(alpha = 0.06f))
                        .padding(16.dp)
                ) {

                    Text(
                        text =
                        "SentriX continuously monitors sensitive permissions, " +
                                "tracking behavior, and suspicious background activities " +
                                "to keep your privacy protected in real time.",
                        color = Color(0xFFECEFF1),
                        fontSize = 13.sp,
                        lineHeight = 20.sp
                    )
                }
            }
        }
    }
}

@Composable
private fun PrivacyMetricItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    value: String,
    label: String
) {

    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {

        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(Color.White.copy(alpha = 0.08f)),
            contentAlignment = Alignment.Center
        ) {

            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = Color.Cyan,
                modifier = Modifier.size(24.dp)
            )
        }

        Spacer(modifier = Modifier.height(10.dp))

        Text(
            text = value,
            color = Color.White,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(4.dp))

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 12.sp
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

PrivacyScoreCard(
    privacy = PrivacyScoreModel(
        privacyScore = 92,
        protectedApps = 48,
        blockedTrackers = 126,
        activeThreats = 3,
        securityStatus = "Excellent Privacy Protection"
    )
)

*/
