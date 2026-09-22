package com.drishti.agent.transport

import android.content.Context
import com.drishti.agent.collectors.AppCollector
import com.drishti.agent.collectors.BatteryCollector
import com.drishti.agent.collectors.CapabilityMatrixCollector
import com.drishti.agent.collectors.CpuCollector
import com.drishti.agent.collectors.DeviceInfoCollector
import com.drishti.agent.collectors.ForegroundAppCollector
import com.drishti.agent.collectors.MemoryCollector
import com.drishti.agent.collectors.NetworkCollector
import com.drishti.agent.collectors.ProcessCollector
import com.drishti.agent.collectors.SecurityCollector
import com.drishti.agent.collectors.StorageCollector
import com.drishti.agent.models.EndpointIdentity
import com.drishti.agent.models.EndpointTelemetryBatch
import com.drishti.agent.services.DrishtiVpnService
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

class TelemetryManager(
    private val context: Context,
    private val apiClient: DrishtiApiClient,
    private val secureStorage: SecureStorage,
    private val identityProvider: () -> EndpointIdentity,
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.IO)
) {
    private val deviceInfoCollector = DeviceInfoCollector(context)
    private val cpuCollector = CpuCollector()
    private val memoryCollector = MemoryCollector(context)
    private val storageCollector = StorageCollector()
    private val batteryCollector = BatteryCollector(context)
    private val networkCollector = NetworkCollector(context)
    private val appCollector = AppCollector(context)
    private val processCollector = ProcessCollector(context)
    private val securityCollector = SecurityCollector(context)
    private val foregroundAppCollector = ForegroundAppCollector(context)
    private val capabilityMatrixCollector = CapabilityMatrixCollector(context)

    private val _lastTelemetrySent = MutableStateFlow<Instant?>(null)
    val lastTelemetrySent: StateFlow<Instant?> = _lastTelemetrySent.asStateFlow()

    private val _latestBatch = MutableStateFlow<EndpointTelemetryBatch?>(null)
    val latestBatch: StateFlow<EndpointTelemetryBatch?> = _latestBatch.asStateFlow()

    private var telemetryJob: Job? = null
    private val telemetryIntervalMs = 45_000L

    fun start() {
        if (telemetryJob?.isActive == true) return

        telemetryJob = scope.launch {
            while (isActive) {
                val token = secureStorage.getAuthToken()
                if (!token.isNullOrBlank()) {
                    collectAndSend(token)
                }
                delay(telemetryIntervalMs)
            }
        }
    }

    suspend fun collectAndSend(token: String? = null): Boolean {
        val authToken = token ?: secureStorage.getAuthToken() ?: return false
        val identity = identityProvider()

        val devInfo = deviceInfoCollector.collect()
        val devInfoTelemetry = deviceInfoCollector.collectTelemetry()
        val uptimeTelemetry = deviceInfoCollector.collectUptime(
            lastHeartbeat = _lastTelemetrySent.value,
            agentServiceRunning = telemetryJob?.isActive == true,
            lastTelemetryUpload = _lastTelemetrySent.value
        )
        val cpu = cpuCollector.collect()
        val mem = memoryCollector.collect()
        val storage = storageCollector.collect()
        val battery = batteryCollector.collect()
        val network = networkCollector.collect()
        val (appTelemetry, softwareTelemetry) = appCollector.collect()
        val processes = processCollector.collect()
        val security = securityCollector.collect()
        val foregroundApp = foregroundAppCollector.collect()
        val browserVisibility = appCollector.collectBrowserVisibility(foregroundApp.package_name)
        val networkFlows = DrishtiVpnService.getRecentFlows()
        val capabilityStatus = capabilityMatrixCollector.collect()

        val batch = EndpointTelemetryBatch(
            agent_id = identity.agent_id,
            device_id = identity.device_id,
            timestamp = Instant.now().toString(),
            hostname = devInfo.deviceName,
            os_name = "android",
            os_version = "Android ${devInfo.androidVersion} (SDK ${devInfo.sdkVersion})",
            endpoint_processes = processes,
            active_apps = processes.map { it.name },
            installed_software = softwareTelemetry,
            services = emptyList(),
            listening_ports = emptyList(),
            process_connections = emptyList(),
            os_info = "Android ${devInfo.androidVersion} [${devInfo.architecture}]",
            device_model = devInfo.model,
            manufacturer = devInfo.manufacturer,
            sdk_version = devInfo.sdkVersion,
            cpu_info = cpu,
            memory_info = mem,
            storage_info = storage,
            battery_info = battery,
            network_info = network,
            security_posture = security,
            applications = appTelemetry,
            // Extended Android telemetry
            device_info = devInfoTelemetry,
            uptime_info = uptimeTelemetry,
            foreground_app = foregroundApp,
            browser_visibility = browserVisibility,
            network_flows = networkFlows,
            capability_status = capabilityStatus
        )

        _latestBatch.value = batch

        return try {
            val response = apiClient.sendTelemetry(authToken, batch)
            if (response.success) {
                _lastTelemetrySent.value = Instant.now()
                true
            } else {
                false
            }
        } catch (_: Exception) {
            false
        }
    }

    fun stop() {
        telemetryJob?.cancel()
        telemetryJob = null
    }
}
