package com.drishti.agent.transport

import com.drishti.agent.models.EndpointIdentity
import com.drishti.agent.models.HeartbeatRequest
import com.drishti.agent.storage.SecureStorage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Instant

enum class HeartbeatState {
    IDLE,
    SENDING,
    ONLINE,
    STALE,
    OFFLINE,
    UNAUTHORIZED
}

class HeartbeatManager(
    private val apiClient: DrishtiApiClient,
    private val secureStorage: SecureStorage,
    private val identityProvider: () -> EndpointIdentity,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) {
    private val _state = MutableStateFlow(HeartbeatState.IDLE)
    val state: StateFlow<HeartbeatState> = _state.asStateFlow()

    private val _lastSuccessfulHeartbeat = MutableStateFlow<Instant?>(null)
    val lastSuccessfulHeartbeat: StateFlow<Instant?> = _lastSuccessfulHeartbeat.asStateFlow()

    private var heartbeatJob: Job? = null
    private val normalIntervalMs = 20_000L
    private val minBackoffMs = 3_000L
    private val maxBackoffMs = 60_000L

    fun start() {
        if (heartbeatJob?.isActive == true) return

        heartbeatJob = scope.launch {
            var currentBackoffMs = minBackoffMs

            while (isActive) {
                val token = secureStorage.getAuthToken()
                if (token.isNullOrBlank()) {
                    _state.value = HeartbeatState.IDLE
                    delay(normalIntervalMs)
                    continue
                }

                _state.value = HeartbeatState.SENDING
                val identity = identityProvider()
                val request = HeartbeatRequest(
                    agent_id = identity.agent_id,
                    device_id = identity.device_id,
                    timestamp = Instant.now().toString(),
                    agent_version = identity.agent_version,
                    collector_health = mapOf(
                        "identity" to "OK",
                        "platform" to "Android_${identity.sdk_version}"
                    ),
                    connectivity = mapOf(
                        "status" to "ONLINE"
                    )
                )

                try {
                    val resp = apiClient.sendHeartbeat(token, request)
                    if (resp.status == "ACK") {
                        _state.value = HeartbeatState.ONLINE
                        _lastSuccessfulHeartbeat.value = Instant.now()
                        currentBackoffMs = minBackoffMs
                        delay(normalIntervalMs)
                    } else {
                        _state.value = HeartbeatState.STALE
                        delay(currentBackoffMs)
                        currentBackoffMs = (currentBackoffMs * 2).coerceAtMost(maxBackoffMs)
                    }
                } catch (e: UnauthorizedException) {
                    _state.value = HeartbeatState.UNAUTHORIZED
                    secureStorage.forceRePair()
                    break
                } catch (e: Exception) {
                    val lastSuccess = _lastSuccessfulHeartbeat.value
                    if (lastSuccess != null && Instant.now().minusSeconds(60).isAfter(lastSuccess)) {
                        _state.value = HeartbeatState.OFFLINE
                    } else {
                        _state.value = HeartbeatState.STALE
                    }

                    delay(currentBackoffMs)
                    currentBackoffMs = (currentBackoffMs * 2).coerceAtMost(maxBackoffMs)
                }
            }
        }
    }

    fun stop() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        _state.value = HeartbeatState.IDLE
    }
}
