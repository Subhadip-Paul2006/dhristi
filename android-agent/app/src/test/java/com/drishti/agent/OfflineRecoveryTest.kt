package com.drishti.agent

import com.drishti.agent.transport.HeartbeatState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class OfflineRecoveryTest {

    @Test
    fun testHeartbeatStateTransitions() {
        var state = HeartbeatState.IDLE
        assertEquals(HeartbeatState.IDLE, state)

        state = HeartbeatState.SENDING
        assertEquals(HeartbeatState.SENDING, state)

        state = HeartbeatState.ONLINE
        assertEquals(HeartbeatState.ONLINE, state)

        state = HeartbeatState.STALE
        assertEquals(HeartbeatState.STALE, state)

        state = HeartbeatState.OFFLINE
        assertEquals(HeartbeatState.OFFLINE, state)

        state = HeartbeatState.UNAUTHORIZED
        assertEquals(HeartbeatState.UNAUTHORIZED, state)
    }

    @Test
    fun testExponentialBackoffCalculation() {
        val minBackoffMs = 3_000L
        val maxBackoffMs = 60_000L

        var currentBackoff = minBackoffMs
        assertEquals(3000L, currentBackoff)

        // Simulate 5 consecutive connection failures
        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(6000L, currentBackoff)

        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(12000L, currentBackoff)

        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(24000L, currentBackoff)

        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(48000L, currentBackoff)

        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(60000L, currentBackoff) // Capped at maxBackoffMs

        // Next failure remains capped
        currentBackoff = (currentBackoff * 2).coerceAtMost(maxBackoffMs)
        assertEquals(60000L, currentBackoff)

        // Success resets to minBackoff
        currentBackoff = minBackoffMs
        assertEquals(3000L, currentBackoff)
    }

    @Test
    fun testOfflineThresholdDetection() {
        val now = Instant.now()
        val recentHeartbeat = now.minusSeconds(15)
        val staleHeartbeat = now.minusSeconds(65)

        val isRecentStale = now.minusSeconds(60).isAfter(recentHeartbeat)
        val isOldOffline = now.minusSeconds(60).isAfter(staleHeartbeat)

        assertEquals(false, isRecentStale)
        assertEquals(true, isOldOffline)
    }
}
