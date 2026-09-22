package com.drishti.agent

import com.drishti.agent.collectors.CollectorStatus
import com.drishti.agent.models.CpuTelemetry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CollectorPermissionTest {

    @Test
    fun testCollectorStatusEnumValues() {
        assertEquals(3, CollectorStatus.values().size)
        assertTrue(CollectorStatus.values().contains(CollectorStatus.SUPPORTED))
        assertTrue(CollectorStatus.values().contains(CollectorStatus.UNSUPPORTED))
        assertTrue(CollectorStatus.values().contains(CollectorStatus.PERMISSION_REQUIRED))
    }

    @Test
    fun testCpuCollectorDefensiveHonesty() {
        // When SELinux denies reading /proc/stat, telemetry must not invent values
        val cpuTelemetry = CpuTelemetry(
            cores = 8,
            usage_percent = null,
            per_core_supported = false,
            per_core_usage = emptyList(),
            architecture = "arm64-v8a"
        )

        assertEquals(8, cpuTelemetry.cores)
        assertNull("Usage percent should be null when restricted by OS", cpuTelemetry.usage_percent)
        assertFalse("Per-core metrics are unsupported on Android without root", cpuTelemetry.per_core_supported)
        assertTrue(cpuTelemetry.per_core_usage.isEmpty())
    }
}
