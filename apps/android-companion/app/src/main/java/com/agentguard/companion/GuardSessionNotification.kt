package com.agentguard.companion

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat

/**
 * User-visible status for an active AccessibilityService-backed session.
 *
 * This is deliberately a normal ongoing notification, not a foreground
 * `dataSync` service. AgentGuard is not uploading, backing up or importing data,
 * and a placeholder dataSync FGS both misrepresented the work and is forcibly
 * timed out on modern Android. The AccessibilityService binding is the actual
 * observer lifecycle; notification permission affects visibility, never whether
 * the UI may claim the observer is active.
 */
object GuardSessionNotification {
    private const val CHANNEL_ID = "agentguard_session"
    private const val NOTIFICATION_ID = 1001

    fun show(context: Context) {
        if (!SessionState.active || !GuardAccessibilityService.isBound()) return
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                LocaleController.text(context, R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        val pending = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(LocaleController.text(context, R.string.notification_title))
            .setContentText(LocaleController.text(context, R.string.notification_text))
            .setSmallIcon(R.drawable.ic_stat_agentguard)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
        try {
            manager.notify(NOTIFICATION_ID, notification)
        } catch (error: SecurityException) {
            // Android 13+ may deny POST_NOTIFICATIONS. The Activity already
            // reports that degraded presentation; it is not observer failure.
            android.util.Log.w("GuardSessionNotice", "notification permission unavailable")
        }
    }

    fun hide(context: Context) {
        val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.cancel(NOTIFICATION_ID)
    }
}
