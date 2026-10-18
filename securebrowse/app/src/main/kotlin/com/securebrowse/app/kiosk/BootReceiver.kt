package com.securebrowse.app.kiosk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.securebrowse.app.SecureBrowseApp
import com.securebrowse.app.ui.MainActivity

/**
 * Device-owner apps may start an activity from boot. Unmanaged installs do
 * not get that exemption, and this receiver does not try to take it.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val graph = SecureBrowseApp.graph(context)
        if (!graph.currentPolicy().kioskAutoStart) return
        if (!KioskController.isDeviceOwner(context)) return
        val launch = Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
    }
}
