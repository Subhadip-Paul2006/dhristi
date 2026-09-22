package com.drishti.agent.collectors

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import com.drishti.agent.models.BatteryTelemetry

class BatteryCollector(private val context: Context) {

    fun collect(): BatteryTelemetry {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryStatus: Intent? = context.registerReceiver(null, filter)

        if (batteryStatus != null) {
            val level: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
            val scale: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
            val percentage: Int = if (level >= 0 && scale > 0) {
                (level * 100) / scale
            } else {
                -1
            }

            val status: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
            val isCharging: Boolean = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                    status == BatteryManager.BATTERY_STATUS_FULL

            val healthInt: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_HEALTH, BatteryManager.BATTERY_HEALTH_UNKNOWN)
            val health: String = when (healthInt) {
                BatteryManager.BATTERY_HEALTH_GOOD -> "GOOD"
                BatteryManager.BATTERY_HEALTH_OVERHEAT -> "OVERHEAT"
                BatteryManager.BATTERY_HEALTH_DEAD -> "DEAD"
                BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "OVER_VOLTAGE"
                BatteryManager.BATTERY_HEALTH_COLD -> "COLD"
                BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "FAILURE"
                else -> "UNKNOWN"
            }

            val tempRaw: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1)
            val temperatureC: Double? = if (tempRaw > 0) tempRaw / 10.0 else null

            // Charging type
            val plugged: Int = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1)
            val chargingType: String? = when (plugged) {
                BatteryManager.BATTERY_PLUGGED_AC -> "AC"
                BatteryManager.BATTERY_PLUGGED_USB -> "USB"
                BatteryManager.BATTERY_PLUGGED_WIRELESS -> "WIRELESS"
                else -> if (isCharging) "UNKNOWN" else null
            }

            // Voltage in mV
            val voltageMv: Int? = batteryStatus.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1).let {
                if (it > 0) it else null
            }

            // Current and capacity via BatteryManager service (API 21+)
            val bm = context.getSystemService(Context.BATTERY_SERVICE) as? BatteryManager
            val currentUa: Int? = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)?.let {
                if (it != 0 && it != Int.MIN_VALUE) it else null
            }
            val capacityUah: Int? = bm?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER)?.let {
                if (it > 0) it else null
            }

            // Power save mode
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            val powerSaveMode = powerManager?.isPowerSaveMode
            val batterySaver = powerSaveMode

            return BatteryTelemetry(
                percentage = percentage,
                charging = isCharging,
                health = health,
                temperature_c = temperatureC,
                charging_type = chargingType,
                voltage_mv = voltageMv,
                current_ua = currentUa,
                capacity_uah = capacityUah,
                power_save_mode = powerSaveMode,
                battery_saver = batterySaver
            )
        }

        return BatteryTelemetry(
            percentage = -1,
            charging = false,
            health = "UNAVAILABLE",
            temperature_c = null
        )
    }
}
