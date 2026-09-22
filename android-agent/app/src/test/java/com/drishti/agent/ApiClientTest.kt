package com.drishti.agent

import com.drishti.agent.models.HeartbeatResponse
import com.drishti.agent.models.PairingInitResponse
import com.drishti.agent.models.PairingStatusResponse
import com.drishti.agent.transport.SessionNotFoundException
import com.drishti.agent.transport.UnauthorizedException
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApiClientTest {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    @Test
    fun testPairingInitResponseDeserialization() {
        val payload = """
        {
            "session_id": "sess-9988",
            "pairing_code": "XY88ZZ",
            "expires_at": "2026-09-21T13:00:00Z",
            "poll_interval_seconds": 3
        }
        """.trimIndent()

        val resp = json.decodeFromString<PairingInitResponse>(payload)
        assertEquals("sess-9988", resp.session_id)
        assertEquals("XY88ZZ", resp.pairing_code)
        assertEquals(3, resp.poll_interval_seconds)
    }

    @Test
    fun testPairingStatusResponseDeserialization() {
        val payload = """
        {
            "status": "PAIRED",
            "agent_token": "jwt-agent-token-xyz",
            "org_id": "default-org"
        }
        """.trimIndent()

        val resp = json.decodeFromString<PairingStatusResponse>(payload)
        assertEquals("PAIRED", resp.status)
        assertEquals("jwt-agent-token-xyz", resp.agent_token)
        assertEquals("default-org", resp.org_id)
    }

    @Test
    fun testHeartbeatResponseDeserialization() {
        val payload = """
        {
            "status": "ACK",
            "server_time": "2026-09-21T12:05:00Z",
            "derived_status": "ONLINE"
        }
        """.trimIndent()

        val resp = json.decodeFromString<HeartbeatResponse>(payload)
        assertEquals("ACK", resp.status)
        assertEquals("2026-09-21T12:05:00Z", resp.server_time)
        assertEquals("ONLINE", resp.derived_status)
    }

    @Test
    fun testExceptionTypes() {
        val unauth = UnauthorizedException("401 Token Expired")
        val notFound = SessionNotFoundException("404 Session Not Found")

        assertTrue(unauth.message!!.contains("401"))
        assertTrue(notFound.message!!.contains("404"))
    }
}
