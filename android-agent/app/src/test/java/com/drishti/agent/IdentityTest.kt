package com.drishti.agent

import com.drishti.agent.models.EndpointIdentity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class IdentityTest {

    @Test
    fun testIdentityCreationAndPlatformConstraints() {
        val agentId = UUID.randomUUID().toString()
        val deviceId = UUID.randomUUID().toString()

        val identity = EndpointIdentity(
            agent_id = agentId,
            device_id = deviceId,
            hostname = "Pixel 8 Pro",
            os = "android",
            os_version = "15",
            mac = null, // In Android 11+, MAC address access is restricted and returns 02:00:00:00:00:00 or null
            current_ip = "192.168.1.150",
            agent_version = "0.1.0",
            manufacturer = "Google",
            model = "Pixel 8 Pro",
            sdk_version = 35,
            created_at = "2026-09-21T12:00:00Z"
        )

        assertEquals("android", identity.os)
        assertEquals(35, identity.sdk_version)
        assertEquals("Google", identity.manufacturer)
        assertEquals("Pixel 8 Pro", identity.model)
        assertNull("Android agents must not report hardware MAC addresses", identity.mac)
        assertNotNull(identity.agent_id)
        assertNotNull(identity.device_id)
        assertTrue(identity.agent_id.isNotEmpty())
    }

    @Test
    fun testIdentitySerializationStructure() {
        val identity = EndpointIdentity(
            agent_id = "test-agent-123",
            device_id = "test-device-456",
            hostname = "Android-Test",
            os = "android",
            os_version = "14",
            mac = null,
            current_ip = "10.0.2.15",
            agent_version = "0.1.0",
            manufacturer = "Android",
            model = "Emulator",
            sdk_version = 34,
            created_at = "2026-09-21T12:00:00Z"
        )

        assertEquals("test-agent-123", identity.agent_id)
        assertEquals("test-device-456", identity.device_id)
    }
}
