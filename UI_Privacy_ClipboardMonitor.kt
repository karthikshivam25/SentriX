package com.sentrix.ui.privacy

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.WarningAmber
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

data class ClipboardMonitorModel(
    val appName: String,
    val copiedContent: String,
    val lastClipboardAccess: String,
    val accessCount: Int,
    val riskLevel: String,
    val clipboardStatus: String,
    val warningMessage: String
)

@Composable
fun ClipboardMonitorCard(
    clipboard: ClipboardMonitorModel,
    modifier: Modifier = Modifier
) {

    val riskColor = when (clipboard.riskLevel) {
        "Critical" -> Color(0xFFFF1744)
        "High" -> Color(0xFFFF9100)
        "Medium" -> Color(0xFFFFC400)
        else -> Color(0xFF00E676)
    }

    val statusColor =
        if (clipboard.clipboardStatus == "Monitoring")
            Color(0xFF00E676)
        else
            Color(0xFFFF5252)

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = Color.Transparent
        ),
        elevation = CardDefaults.cardElevation(
            defaultElevation = 10.dp
        )
    ) {

        Box(
            modifier = Modifier
                .background(
                    brush = Brush.linearGradient(
                        colors = listOf(
                            Color(0xFF111827),
                            Color(0xFF0F172A)
                        )
                    )
                )
                .padding(22.dp)
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
                            .size(60.dp)
                            .clip(CircleShape)
                            .background(riskColor.copy(alpha = 0.15f)),
                        contentAlignment = Alignment.Center
                    ) {

                        Icon(
                            imageVector = Icons.Default.ContentPaste,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(32.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    Column(
                        modifier = Modifier.weight(1f)
                    ) {

                        Text(
                            text = clipboard.appName,
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = "Clipboard Privacy Monitor",
                            color = Color(0xFF90A4AE),
                            fontSize = 13.sp
                        )
                    }

                    Surface(
                        shape = RoundedCornerShape(50),
                        color = statusColor.copy(alpha = 0.15f)
                    ) {

                        Text(
                            text = clipboard.clipboardStatus,
                            color = statusColor,
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 6.dp
                            ),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                ClipboardInfoRow(
                    label = "Last Access",
                    value = clipboard.lastClipboardAccess,
                    valueColor = Color.White
                )

                ClipboardInfoRow(
                    label = "Access Count",
                    value = "${clipboard.accessCount} Times",
                    valueColor = Color.White
                )

                ClipboardInfoRow(
                    label = "Risk Level",
                    value = clipboard.riskLevel,
                    valueColor = riskColor
                )

                Spacer(modifier = Modifier.height(20.dp))

                // Clipboard Preview Box
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(Color(0xFF1E293B))
                        .padding(16.dp)
                ) {

                    Column {

                        Row(
                            verticalAlignment = Alignment.CenterVertically
                        ) {

                            Icon(
                                imageVector = Icons.Default.Lock,
                                contentDescription = null,
                                tint = Color.Cyan,
                                modifier = Modifier.size(20.dp)
                            )

                            Spacer(modifier = Modifier.width(8.dp))

                            Text(
                                text = "Clipboard Snapshot",
                                color = Color.White,
                                fontWeight = FontWeight.SemiBold,
                                fontSize = 14.sp
                            )
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        Text(
                            text = clipboard.copiedContent,
                            color = Color(0xFFECEFF1),
                            fontSize = 13.sp,
                            maxLines = 3,
                            overflow = TextOverflow.Ellipsis,
                            lineHeight = 20.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(18.dp))

                // Warning Box
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(18.dp))
                        .background(riskColor.copy(alpha = 0.12f))
                        .padding(16.dp)
                ) {

                    Row(
                        verticalAlignment = Alignment.Top
                    ) {

                        Icon(
                            imageVector = Icons.Default.WarningAmber,
                            contentDescription = null,
                            tint = riskColor,
                            modifier = Modifier.size(22.dp)
                        )

                        Spacer(modifier = Modifier.width(12.dp))

                        Text(
                            text = clipboard.warningMessage,
                            color = Color(0xFFECEFF1),
                            fontSize = 13.sp,
                            lineHeight = 20.sp
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                // Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {

                    Button(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF00BCD4)
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.Security,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Protect")
                    }

                    OutlinedButton(
                        onClick = { },
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.Red
                        )
                    ) {

                        Icon(
                            imageVector = Icons.Default.ContentPaste,
                            contentDescription = null
                        )

                        Spacer(modifier = Modifier.width(8.dp))

                        Text(text = "Clear")
                    }
                }
            }
        }
    }
}

@Composable
private fun ClipboardInfoRow(
    label: String,
    value: String,
    valueColor: Color
) {

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 7.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {

        Text(
            text = label,
            color = Color(0xFF90A4AE),
            fontSize = 13.sp
        )

        Text(
            text = value,
            color = valueColor,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold
        )
    }
}

/*
---------------------------------------------------
SAMPLE USAGE
---------------------------------------------------

ClipboardMonitorCard(
    clipboard = ClipboardMonitorModel(
        appName = "Browser",
        copiedContent = "OTP: 482991 | Bank Verification Code",
        lastClipboardAccess = "1 min ago",
        accessCount = 6,
        riskLevel = "High",
        clipboardStatus = "Monitoring",
        warningMessage =
        "Sensitive clipboard content detected. Some applications " +
        "may attempt to read copied passwords, OTPs, or banking data."
    )
)

*/
