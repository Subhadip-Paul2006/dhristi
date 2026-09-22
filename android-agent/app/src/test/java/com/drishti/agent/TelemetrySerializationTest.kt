package com.drishti.agent

import com.drishti.agent.models.AppTelemetryItem
import com.drishti.agent.models.BatteryTelemetry
import com.drishti.agent.models.CpuTelemetry
import com.drishti.agent.models.EndpointTelemetryBatch
import com.drishti.agent.models.MemoryTelemetry
import com.drishti.agent.models.NetworkTelemetry
import com.drishti.agent.models.ProcessTelemetryItem
import com.drishti.agent.models.SecurityPostureTelemetry
import com.drishti.agent.models.SoftwareTelemetryItem
import com.drishti.agent.models.StorageTelemetry
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TelemetrySerializationTest {

    private val json = Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    @Test
    fun testEndpointTelemetryBatchSerialization() {
        val batch = EndpointTelemetryBatch(
            agent_id = "agent-android-12345",
            device_id = "device-android-67890",
            timestamp = "2026-09-21T12:00:00Z",
            hostname = "Pixel 9 Pro",
            os_name = "android",
            os_version = "Android 15 (SDK 35)",
            endpoint_processes = listOf(
                ProcessTelemetryItem(
                    pid = 1234,
                    name = "com.drishti.agent",
                    cpu_percent = 0.5,
                    memory_mb = 45.2
                )
            ),
            active_apps = listOf("com.drishti.agent"),
            installed_software = listOf(
                SoftwareTelemetryItem(
                    name = "Google Chrome",
                    version = "130.0.6723.58",
                    vendor = "com.android.chrome",
                    source = "android_package"
                )
            ),
            device_model = "Pixel 9 Pro",
            manufacturer = "Google",
            sdk_version = 35,
            cpu_info = CpuTelemetry(
                cores = 8,
                usage_percent = null, // Honestly null because SELinux restricts global /proc/stat
                per_core_supported = false,
                per_core_usage = emptyList(),
                architecture = "arm64-v8a"
            ),
            memory_info = MemoryTelemetry(
                total_bytes = 12_884_901_888L,
                available_bytes = 6_442_450_944L,
                used_bytes = 6_442_450_944L,
                low_memory = false
            ),
            storage_info = StorageTelemetry(
                total_bytes = 256_000_000_000L,
                available_bytes = 128_000_000_000L,
                used_bytes = 128_000_000_000L
            ),
            battery_info = BatteryTelemetry(
                percentage = 85,
                charging = true,
                health = "GOOD",
                temperature_c = 28.5
            ),
            network_info = NetworkTelemetry(
                connection_type = "WI-FI",
                local_ip = "192.168.1.150",
                interface_name = "wlan0",
                link_speed_kbps = 866000
            ),
            security_posture = SecurityPostureTelemetry(
                screen_lock = true,
                encryption = "ENCRYPTED",
                developer_options = false,
                usb_debugging = false,
                verified_boot = "release-keys",
                security_patch = "2026-09-01",
                biometric_capability = "BIOMETRIC_STRONG",
                root_detected = false
            ),
            applications = listOf(
                AppTelemetryItem(
                    package_name = "com.android.chrome",
                    label = "Chrome",
                    version_name = "130.0.6723.58",
                    version_code = 672305800L,
                    classification = "USER_APP",
                    is_enabled = true
                )
            )
        )

        val serializedJson = json.encodeToString(EndpointTelemetryBatch.serializer(), batch)

        // Verify key telemetry properties in serialized string
        assertTrue(serializedJson.contains("\"agent_id\": \"agent-android-12345\""))
        assertTrue(serializedJson.contains("\"device_model\": \"Pixel 9 Pro\""))
        assertTrue(serializedJson.contains("\"manufacturer\": \"Google\""))
        assertTrue(serializedJson.contains("\"sdk_version\": 35"))
        assertTrue(serializedJson.contains("\"per_core_supported\": false"))
        assertTrue(serializedJson.contains("\"connection_type\": \"WI-FI\""))
        assertTrue(serializedJson.contains("\"root_detected\": false"))

        // Deserialize back
        val deserialized = json.decodeFromString(EndpointTelemetryBatch.serializer(), serializedJson)
        assertEquals("agent-android-12345", deserialized.agent_id)
        assertEquals(35, deserialized.sdk_version)
        assertEquals("Pixel 9 Pro", deserialized.device_model)
        assertFalse(deserialized.cpu_info!!.per_core_supported)
        assertEquals(85, deserialized.battery_info!!.percentage)
        assertEquals("com.android.chrome", deserialized.applications[0].package_name)
    }
}
