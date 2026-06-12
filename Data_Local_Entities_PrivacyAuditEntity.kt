package com.sentrix.data.local.entities

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.Date

@Entity(tableName = "privacy_audits")
data class PrivacyAuditEntity(

    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,

    val auditId: String,

    val appPackageName: String,

    val appName: String,

    val privacyRiskLevel: String,

    val permissionsGranted: List<String>,

    val sensitivePermissions: List<String>,

    val dataAccessed: List<String>,

    val trackersDetected: Int,

    val suspiciousBehaviors: List<String>,

    val privacyScore: Int,

    val recommendation: String,

    val isCompliant: Boolean,

    val auditDate: Date,

    val lastReviewed: Date? = null,

    val createdAt: Date = Date(),

    val updatedAt: Date = Date()
)
