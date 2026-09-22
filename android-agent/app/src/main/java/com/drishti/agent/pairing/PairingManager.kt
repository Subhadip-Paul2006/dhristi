package com.drishti.agent.pairing

import com.drishti.agent.models.EndpointIdentity
import com.drishti.agent.storage.SecureStorage
import com.drishti.agent.transport.DrishtiApiClient
import com.drishti.agent.transport.TransportException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Deterministic pairing states as specified in Section 9 of the Drishti specification.
 */
enum class PairingState {
    UNPAIRED,
    PAIRING,
    PAIRED,
    CONNECTING,
    CONNECTED,
    OFFLINE,
    ERROR
}

/**
 * Rich UI state representing the pairing lifecycle with associated metadata.
 */
sealed class PairingUiState(val state: PairingState) {
    object Unpaired : PairingUiState(PairingState.UNPAIRED)
    object Initializing : PairingUiState(PairingState.PAIRING)
    data class WaitingForOperator(
        val pairingCode: String,
        val sessionId: String,
        val expiresAt: String,
        val isDemo: Boolean = false
    ) : PairingUiState(PairingState.PAIRING)
    object Connecting : PairingUiState(PairingState.CONNECTING)
    object Paired : PairingUiState(PairingState.PAIRED)
    object Connected : PairingUiState(PairingState.CONNECTED)
    data class Offline(val reason: String = "Network connection unavailable") : PairingUiState(PairingState.OFFLINE)
    data class Expired(val reason: String) : PairingUiState(PairingState.UNPAIRED)
    data class Error(val message: String) : PairingUiState(PairingState.ERROR)
}

class PairingManager(
    private val apiClient: DrishtiApiClient,
    private val secureStorage: SecureStorage,
    private val identityProvider: () -> EndpointIdentity,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) {
    private val _uiState = MutableStateFlow<PairingUiState>(
        if (secureStorage.isPaired()) PairingUiState.Connected else PairingUiState.Unpaired
    )
    val uiState: StateFlow<PairingUiState> = _uiState.asStateFlow()

    val currentState: PairingState
        get() = _uiState.value.state

    private var pollingJob: Job? = null

    fun initiatePairing() {
        if (secureStorage.isPaired()) {
            _uiState.value = PairingUiState.Connected
            return
        }

        pollingJob?.cancel()
        _uiState.value = PairingUiState.Initializing

        scope.launch {
            try {
                val identity = identityProvider()
                val isDemo = secureStorage.isDemoMode()
                val initResponse = apiClient.initPairing(identity, isDemo = isDemo)

                _uiState.value = PairingUiState.WaitingForOperator(
                    pairingCode = initResponse.pairing_code,
                    sessionId = initResponse.session_id,
                    expiresAt = initResponse.expires_at,
                    isDemo = isDemo
                )

                startPolling(initResponse.session_id, identity.agent_id, initResponse.poll_interval_seconds)
            } catch (e: Exception) {
                if (e is TransportException) {
                    _uiState.value = PairingUiState.Offline(e.message ?: "Backend unreachable")
                } else {
                    _uiState.value = PairingUiState.Error(e.message ?: "Failed to initialize pairing session")
                }
            }
        }
    }

    private fun startPolling(sessionId: String, agentId: String, intervalSeconds: Int) {
        pollingJob = scope.launch {
            val delayMs = (intervalSeconds.coerceAtLeast(2)) * 1000L
            var consecutiveNetworkErrors = 0

            while (isActive) {
                delay(delayMs)
                try {
                    val statusResponse = apiClient.checkPairingStatus(sessionId, agentId)
                    consecutiveNetworkErrors = 0

                    when (statusResponse.status) {
                        "PAIRED" -> {
                            val token = statusResponse.agent_token
                            if (!token.isNullOrBlank()) {
                                _uiState.value = PairingUiState.Connecting
                                secureStorage.saveAuth(token, statusResponse.org_id)
                                _uiState.value = PairingUiState.Paired
                                delay(300)
                                _uiState.value = PairingUiState.Connected
                                break
                            }
                        }
                        "EXPIRED" -> {
                            _uiState.value = PairingUiState.Expired("Pairing code expired. Please initiate pairing again.")
                            break
                        }
                        "REJECTED" -> {
                            _uiState.value = PairingUiState.Error("Pairing request was rejected by operator.")
                            break
                        }
                        "WAITING_FOR_PAIR" -> {
                            // Continue polling
                        }
                    }
                } catch (e: Exception) {
                    consecutiveNetworkErrors++
                    if (consecutiveNetworkErrors >= 5 && _uiState.value is PairingUiState.WaitingForOperator) {
                        // Keep waiting state visible but note network hiccups
                    }
                }
            }
        }
    }

    fun markConnected() {
        if (secureStorage.isPaired()) {
            _uiState.value = PairingUiState.Connected
        }
    }

    fun markOffline(reason: String = "Connectivity lost") {
        if (_uiState.value !is PairingUiState.WaitingForOperator) {
            _uiState.value = PairingUiState.Offline(reason)
        }
    }

    fun forceRePair() {
        pollingJob?.cancel()
        pollingJob = null
        secureStorage.forceRePair()
        _uiState.value = PairingUiState.Unpaired
        initiatePairing()
    }

    fun stop() {
        pollingJob?.cancel()
        pollingJob = null
    }
}
