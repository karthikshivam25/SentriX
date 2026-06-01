package com.sentrix.ui.theme

import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/*
|--------------------------------------------------------------------------
| SENTRIX - ENTERPRISE UI COLOR SYSTEM
|--------------------------------------------------------------------------
|
| PURPOSE:
| Complete centralized visual identity system for SentriX.
|
| This file controls:
|
| - Brand Colors
| - Dashboard Colors
| - Security Threat Colors
| - AI Monitoring Colors
| - Dark Mode Colors
| - Premium Neon Effects
| - Glassmorphism Layers
| - Gradients
| - Graph Visualization Colors
| - Authentication Colors
| - Network Monitoring Colors
| - System Health Colors
| - Notification Colors
| - Future Expansion Tokens
|
|--------------------------------------------------------------------------
| IMPORTANT RULES
|--------------------------------------------------------------------------
|
| 1. NEVER hardcode colors inside UI screens.
| 2. ALWAYS import colors from this file.
| 3. Future themes should extend this system.
| 4. All SentriX modules must follow this design system.
|
|--------------------------------------------------------------------------
*/



/* =========================================================
   CORE BRAND COLORS
   ========================================================= */

val SentriX_PrimaryBlue = Color(0xFF0066FF)

val SentriX_SecondaryBlue = Color(0xFF0047B3)

val SentriX_AccentCyan = Color(0xFF00E5FF)

val SentriX_AccentPurple = Color(0xFF8B5CF6)

val SentriX_AccentMagenta = Color(0xFFFF00FF)

val SentriX_AccentTeal = Color(0xFF00FFC6)



/* =========================================================
   MAIN BACKGROUND SYSTEM
   ========================================================= */

val Background_Main = Color(0xFF070B14)

val Background_Secondary = Color(0xFF0F172A)

val Background_Tertiary = Color(0xFF131C31)

val Background_Card = Color(0xFF1A2338)

val Background_Popup = Color(0xFF202B45)

val Background_Overlay = Color(0xAA000000)

val Background_BlurLayer = Color(0x66FFFFFF)



/* =========================================================
   TEXT SYSTEM
   ========================================================= */

val Text_Primary = Color(0xFFFFFFFF)

val Text_Secondary = Color(0xFFB8C1D1)

val Text_Muted = Color(0xFF7B879D)

val Text_Disabled = Color(0xFF5A6478)

val Text_Dark = Color(0xFF101010)

val Text_Highlight = SentriX_AccentCyan



/* =========================================================
   BUTTON SYSTEM
   ========================================================= */

val Button_Primary = SentriX_PrimaryBlue

val Button_PrimaryHover = Color(0xFF3385FF)

val Button_Secondary = Color(0xFF1E293B)

val Button_Disabled = Color(0xFF4B5563)

val Button_Danger = Color(0xFFFF3B30)

val Button_Success = Color(0xFF00C853)



/* =========================================================
   BORDER & DIVIDER SYSTEM
   ========================================================= */

val Border_Light = Color(0xFF2C3A52)

val Border_Strong = Color(0xFF4C5D7A)

val Border_Glow = SentriX_AccentCyan

val Divider_Color = Color(0xFF25324A)



/* =========================================================
   SECURITY THREAT LEVEL COLORS
   ========================================================= */

val Threat_Low = Color(0xFF00C853)

val Threat_Medium = Color(0xFFFFC107)

val Threat_High = Color(0xFFFF7043)

val Threat_Critical = Color(0xFFFF1744)

val Threat_Severe = Color(0xFFB00020)



/* =========================================================
   AI MONITORING COLORS
   ========================================================= */

val AI_Active = Color(0xFF00E5FF)

val AI_Thinking = Color(0xFF7C4DFF)

val AI_Analyzing = Color(0xFFFFEA00)

val AI_Error = Color(0xFFFF1744)



/* =========================================================
   NETWORK TRAFFIC COLORS
   ========================================================= */

val Network_Incoming = Color(0xFF00E676)

val Network_Outgoing = Color(0xFF29B6F6)

val Network_Suspicious = Color(0xFFFF9100)

val Network_Blocked = Color(0xFFD50000)



/* =========================================================
   AUTHENTICATION COLORS
   ========================================================= */

val Auth_Login = Color(0xFF00B0FF)

val Auth_Verified = Color(0xFF00C853)

val Auth_Failed = Color(0xFFFF3D00)

val Auth_MFA = Color(0xFFAA00FF)



/* =========================================================
   NOTIFICATION COLORS
   ========================================================= */

val Notification_Info = Color(0xFF2196F3)

val Notification_Success = Color(0xFF00C853)

val Notification_Warning = Color(0xFFFFC107)

val Notification_Error = Color(0xFFFF3B30)



/* =========================================================
   DASHBOARD CARD COLORS
   ========================================================= */

val Dashboard_Blue = Color(0xFF102A43)

val Dashboard_Purple = Color(0xFF2D1B4E)

val Dashboard_Green = Color(0xFF123524)

val Dashboard_Red = Color(0xFF3B1010)

val Dashboard_Cyan = Color(0xFF003F5C)



/* =========================================================
   GRAPH & ANALYTICS COLORS
   ========================================================= */

val Graph_LineBlue = Color(0xFF29B6F6)

val Graph_LineGreen = Color(0xFF66BB6A)

val Graph_LineYellow = Color(0xFFFFCA28)

val Graph_LineRed = Color(0xFFEF5350)

val Graph_Background = Color(0xFF0F172A)



/* =========================================================
   TERMINAL / CYBER CONSOLE COLORS
   ========================================================= */

val Terminal_Background = Color(0xFF000000)

val Terminal_Green = Color(0xFF00FF66)

val Terminal_Blue = Color(0xFF00B0FF)

val Terminal_Red = Color(0xFFFF1744)

val Terminal_Orange = Color(0xFFFF9100)



/* =========================================================
   GLASSMORPHISM EFFECTS
   ========================================================= */

val Glass_Light = Color(0x33FFFFFF)

val Glass_Medium = Color(0x22FFFFFF)

val Glass_Strong = Color(0x44FFFFFF)



/* =========================================================
   SHADOW SYSTEM
   ========================================================= */

val Shadow_Soft = Color(0x33000000)

val Shadow_Medium = Color(0x55000000)

val Shadow_Strong = Color(0x88000000)



/* =========================================================
   CYBER GRID / HOLOGRAPHIC EFFECTS
   ========================================================= */

val CyberGrid_Blue = Color(0x2200E5FF)

val CyberGrid_Purple = Color(0x228B5CF6)

val Hologram_Cyan = Color(0x9900E5FF)

val Hologram_Blue = Color(0x660066FF)



/* =========================================================
   LOADING & SYSTEM STATUS COLORS
   ========================================================= */

val System_Loading = Color(0xFF29B6F6)

val System_Healthy = Color(0xFF00C853)

val System_Warning = Color(0xFFFFC107)

val System_Critical = Color(0xFFFF1744)

val System_Offline = Color(0xFF616161)



/* =========================================================
   PREMIUM GRADIENT SYSTEM
   ========================================================= */

val Gradient_Primary = Brush.horizontalGradient(
    colors = listOf(
        SentriX_PrimaryBlue,
        SentriX_AccentCyan
    )
)

val Gradient_Cyber = Brush.linearGradient(
    colors = listOf(
        Color(0xFF00E5FF),
        Color(0xFF0066FF),
        Color(0xFF7B2FFF)
    )
)

val Gradient_Danger = Brush.horizontalGradient(
    colors = listOf(
        Color(0xFFFF1744),
        Color(0xFFFF9100)
    )
)

val Gradient_Success = Brush.horizontalGradient(
    colors = listOf(
        Color(0xFF00C853),
        Color(0xFF00E676)
    )
)



/* =========================================================
   FUTURE EXPANSION TOKENS
   ========================================================= */

val Quantum_Mode = Color(0xFF651FFF)

val Blockchain_Verified = Color(0xFFF7931A)

val ZeroTrust_Active = Color(0xFF00E5FF)

val Satellite_Tracking = Color(0xFF2979FF)

val Biometric_Active = Color(0xFF00C853)



/*
|--------------------------------------------------------------------------
| END OF SENTRIX COLOR SYSTEM
|--------------------------------------------------------------------------
|
| FUTURE UPGRADE IDEAS:
|
| - Dynamic Runtime Theme Engine
| - Multi-Company White Label Themes
| - AMOLED Theme
| - AI Adaptive Themes
| - User Custom Themes
| - Holographic UI Effects
| - Animated Neon Pulse System
| - Cyberpunk Theme Pack
| - Accessibility Themes
| - Military Security Theme
|
|--------------------------------------------------------------------------
*/
