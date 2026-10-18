package com.securebrowse.app.kiosk

import android.app.ActivityManager
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.Build
import android.os.UserManager
import com.securebrowse.policy.BrowserPolicy
import com.securebrowse.policy.KioskSnapshot
import com.securebrowse.policy.LockPresentation
import com.securebrowse.policy.ManagementPosture

object KioskController {
    fun adminComponent(context: Context): ComponentName {
        return ComponentName(context, SecureBrowseDeviceAdminReceiver::class.java)
    }

    fun isDeviceOwner(context: Context): Boolean {
        val dpm = context.getSystemService(DevicePolicyManager::class.java) ?: return false
        return dpm.isDeviceOwnerApp(context.packageName)
    }

    fun snapshot(context: Context): KioskSnapshot {
        val owner = isDeviceOwner(context)
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val permitted = owner && dpm?.isLockTaskPermitted(context.packageName) == true
        return KioskSnapshot(
            posture = if (owner) ManagementPosture.DEVICE_OWNER else ManagementPosture.UNMANAGED,
            lockTaskPermitted = permitted,
            lockTaskMode = presentation(context),
        )
    }

    fun presentation(context: Context): LockPresentation {
        val am = context.getSystemService(ActivityManager::class.java) ?: return LockPresentation.NOT_LOCKED
        return when (am.lockTaskModeState) {
            ActivityManager.LOCK_TASK_MODE_LOCKED -> LockPresentation.DEDICATED_KIOSK
            ActivityManager.LOCK_TASK_MODE_PINNED -> LockPresentation.SCREEN_PINNING
            else -> LockPresentation.NOT_LOCKED
        }
    }

    fun applyPolicies(context: Context, policy: BrowserPolicy): String {
        if (!isDeviceOwner(context)) {
            return "SecureBrowse is not the device owner. These controls are unavailable in normal browser mode."
        }
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return "Device policy service is unavailable."
        val admin = adminComponent(context)
        return try {
            dpm.setLockTaskPackages(admin, arrayOf(context.packageName))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                dpm.setLockTaskFeatures(admin, DevicePolicyManager.LOCK_TASK_FEATURE_NONE)
            }
            dpm.setUninstallBlocked(admin, context.packageName, true)
            baseRestrictions().forEach { dpm.addUserRestriction(admin, it) }
            if (policy.strictKioskRestrictions) {
                dpm.addUserRestriction(admin, UserManager.DISALLOW_DEBUGGING_FEATURES)
                dpm.addUserRestriction(admin, UserManager.DISALLOW_USB_FILE_TRANSFER)
                dpm.setKeyguardDisabled(admin, true)
            } else {
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_DEBUGGING_FEATURES)
                dpm.clearUserRestriction(admin, UserManager.DISALLOW_USB_FILE_TRANSFER)
                dpm.setKeyguardDisabled(admin, false)
            }
            "Device-owner policies applied. Only SecureBrowse may enter lock task."
        } catch (ex: SecurityException) {
            "Device policy was rejected: ${ex.javaClass.simpleName}."
        }
    }

    fun clearDeviceOwnerForAdbTest(context: Context): String {
        if (!isDeviceOwner(context)) return "This app is not the device owner."
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return "Device policy service is unavailable."
        return try {
            dpm.clearDeviceOwnerApp(context.packageName)
            "Device-owner role removed. This succeeds only for test devices provisioned with adb."
        } catch (ex: SecurityException) {
            "The role was not removed. Provisioned devices usually need a factory reset."
        }
    }

    private fun baseRestrictions(): List<String> {
        val values = mutableListOf(
            UserManager.DISALLOW_SAFE_BOOT,
            UserManager.DISALLOW_FACTORY_RESET,
            UserManager.DISALLOW_ADD_USER,
            UserManager.DISALLOW_MOUNT_PHYSICAL_MEDIA,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            values += UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY
        } else {
            @Suppress("DEPRECATION")
            values += UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES
        }
        return values
    }
}
