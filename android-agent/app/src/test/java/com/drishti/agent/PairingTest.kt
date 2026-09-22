package com.drishti.agent

import com.drishti.agent.pairing.PairingUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingTest {

    @Test
    fun testPairingUiStateTransitions() {
        var state: PairingUiState = PairingUiState.Unpaired
        assertEquals(PairingUiState.Unpaired, state)

        state = PairingUiState.Initializing
        assertEquals(PairingUiState.Initializing, state)

        val waiting = PairingUiState.WaitingForOperator(
            pairingCode = "ABC123",
            sessionId = "session-xyz",
            expiresAt = "2026-09-21T12:15:00Z"
        )
        state = waiting
        assertEquals("ABC123", (state as PairingUiState.WaitingForOperator).pairingCode)
        assertEquals("session-xyz", state.sessionId)

        state = PairingUiState.Paired
        assertEquals(PairingUiState.Paired, state)

        state = PairingUiState.Connecting
        assertEquals(PairingUiState.Connecting, state)

        state = PairingUiState.Connected
        assertEquals(PairingUiState.Connected, state)

        state = PairingUiState.Offline("No route to host")
        assertTrue((state as PairingUiState.Offline).reason.contains("No route"))

        val expired = PairingUiState.Expired("Session expired")
        state = expired
        assertTrue((state as PairingUiState.Expired).reason.contains("expired"))

        val error = PairingUiState.Error("Network failure")
        state = error
        assertEquals("Network failure", (state as PairingUiState.Error).message)
    }

    @Test
    fun testPairingCodeFormat() {
        // Drishti pairing codes support 6-char legacy and 8-char standard / demo (ABCD-1234 or ABCD1234)
        val regex = Regex("^[A-Z0-9]{4}-?[A-Z0-9]{4}$|^[A-Z0-9]{6}$")
        assertTrue("ABCD-1234".matches(regex))
        assertTrue("ABCD1234".matches(regex))
        assertTrue("K9X2-M4P7".matches(regex))
        assertTrue("K9X2M4".matches(regex))
    }
}
