package com.drishti.agent.models

import kotlinx.serialization.Serializable

@Serializable
data class PairingInitRequest(
    val agent_id: String,
    val device_id: String,
    val hostname: String,
    val os: String = "android",
    val os_version: String,
    val mac: String? = null,
    val current_ip: String? = null,
    val agent_version: String = "0.1.0",
    val is_demo: Boolean = false
)

@Serializable
data class PairingInitResponse(
    val session_id: String,
    val pairing_code: String,
    val expires_at: String,
    val poll_interval_seconds: Int = 3
)

@Serializable
data class PairingStatusRequest(
    val session_id: String,
    val agent_id: String
)

@Serializable
data class PairingStatusResponse(
    val status: String, // WAITING_FOR_PAIR, PAIRED, CONSUMED, EXPIRED, REJECTED
    val agent_token: String? = null,
    val org_id: String? = null
)

@Serializable
data class HeartbeatRequest(
    val agent_id: String,
    val device_id: String,
    val timestamp: String,
    val agent_version: String = "0.1.0",
    val collector_health: Map<String, String> = emptyMap(),
    val connectivity: Map<String, String> = emptyMap()
)

@Serializable
data class HeartbeatResponse(
    val status: String,
    val server_time: String,
    val derived_status: String
)
