package com.drishti.agent.models

import kotlinx.serialization.Serializable

@Serializable
data class EndpointIdentity(
    val agent_id: String,
    val device_id: String,
    val hostname: String,
    val os: String = "android",
    val os_version: String,
    val mac: String? = null,
    val current_ip: String? = null,
    val agent_version: String = "0.1.0",
    val manufacturer: String = "Unknown",
    val model: String = "Unknown",
    val sdk_version: Int = 0,
    val created_at: String
)
