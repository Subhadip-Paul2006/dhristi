package com.drishti.agent.transport

import com.drishti.agent.models.EndpointIdentity
import com.drishti.agent.models.EndpointTelemetryBatch
import com.drishti.agent.models.EndpointTelemetrySubmitResponse
import com.drishti.agent.models.HeartbeatRequest
import com.drishti.agent.models.HeartbeatResponse
import com.drishti.agent.models.PairingInitRequest
import com.drishti.agent.models.PairingInitResponse
import com.drishti.agent.models.PairingStatusRequest
import com.drishti.agent.models.PairingStatusResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

open class TransportException(message: String, cause: Throwable? = null) : IOException(message, cause)
class UnauthorizedException(message: String) : TransportException(message)
class SessionNotFoundException(message: String) : TransportException(message)

class DrishtiApiClient(
    private val baseUrlProvider: () -> String,
    private val client: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()
) {
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }

    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    private fun getBaseUrl(): String = baseUrlProvider().trimEnd('/')

    suspend fun initPairing(identity: EndpointIdentity, isDemo: Boolean = false): PairingInitResponse = withContext(Dispatchers.IO) {
        val url = "${getBaseUrl()}/api/endpoint/pairing/init"
        val reqBody = PairingInitRequest(
            agent_id = identity.agent_id,
            device_id = identity.device_id,
            hostname = identity.hostname,
            os = "android",
            os_version = identity.os_version,
            mac = identity.mac,
            current_ip = identity.current_ip,
            agent_version = identity.agent_version,
            is_demo = isDemo
        )
        val bodyStr = json.encodeToString(reqBody)
        val request = Request.Builder()
            .url(url)
            .post(bodyStr.toRequestBody(jsonMediaType))
            .header("Accept", "application/json")
            .header("User-Agent", "Drishti-Android-Agent/${identity.agent_version}")
            .build()

        executeRequest(request) { responseBody ->
            json.decodeFromString<PairingInitResponse>(responseBody)
        }
    }

    suspend fun checkPairingStatus(sessionId: String, agentId: String): PairingStatusResponse = withContext(Dispatchers.IO) {
        val url = "${getBaseUrl()}/api/endpoint/pairing/status"
        val reqBody = PairingStatusRequest(session_id = sessionId, agent_id = agentId)
        val bodyStr = json.encodeToString(reqBody)
        val request = Request.Builder()
            .url(url)
            .post(bodyStr.toRequestBody(jsonMediaType))
            .header("Accept", "application/json")
            .build()

        executeRequest(request) { responseBody ->
            json.decodeFromString<PairingStatusResponse>(responseBody)
        }
    }

    suspend fun sendHeartbeat(token: String, requestPayload: HeartbeatRequest): HeartbeatResponse = withContext(Dispatchers.IO) {
        val url = "${getBaseUrl()}/api/endpoint/heartbeat"
        val bodyStr = json.encodeToString(requestPayload)
        val request = Request.Builder()
            .url(url)
            .post(bodyStr.toRequestBody(jsonMediaType))
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/json")
            .build()

        executeRequest(request) { responseBody ->
            json.decodeFromString<HeartbeatResponse>(responseBody)
        }
    }

    suspend fun sendTelemetry(token: String, batch: EndpointTelemetryBatch): EndpointTelemetrySubmitResponse = withContext(Dispatchers.IO) {
        val url = "${getBaseUrl()}/api/endpoint/telemetry"
        val bodyStr = json.encodeToString(batch)
        val request = Request.Builder()
            .url(url)
            .post(bodyStr.toRequestBody(jsonMediaType))
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/json")
            .build()

        executeRequest(request) { responseBody ->
            json.decodeFromString<EndpointTelemetrySubmitResponse>(responseBody)
        }
    }

    private fun <T> executeRequest(request: Request, parser: (String) -> T): T {
        try {
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                when (response.code) {
                    200, 201 -> return parser(body)
                    401 -> throw UnauthorizedException("Unauthorized (401)")
                    404 -> throw SessionNotFoundException("Not Found (404)")
                    else -> throw TransportException("HTTP ${response.code}: $body")
                }
            }
        } catch (e: Exception) {
            if (e is TransportException) throw e
            throw TransportException("Network connection failed: ${e.localizedMessage}", e)
        }
    }
}
