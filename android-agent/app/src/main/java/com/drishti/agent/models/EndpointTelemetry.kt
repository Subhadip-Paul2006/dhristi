package com.drishti.agent.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class ProcessTelemetryItem(
    val pid: Int,
    val name: String,
    val category: String = "USER_APPLICATION",
    val cpu_percent: Double? = null,
    val memory_mb: Double? = null,
    val exe_path: String? = null,
    val username: String? = null,
    val started_at: String? = null,
    val observed_at: String? = null
)

@Serializable
data class SoftwareTelemetryItem(
    val name: String,
    val version: String? = null,
    val vendor: String? = null,
    val install_date: String? = null,
    val install_location: String? = null,
    val source: String = "android_package",
    val observed_at: String? = null
)

@Serializable
data class ServiceTelemetryItem(
    val name: String,
    val display_name: String,
    val status: String,
    val start_type: String = "AUTOMATIC",
    val pid: Int? = null,
    val observed_at: String? = null
)

@Serializable
data class ListeningPortTelemetryItem(
    val port: Int,
    val protocol: String = "TCP",
    val bind_address: String = "0.0.0.0",
    val pid: Int? = null,
    val process_name: String? = null,
    val observed_at: String? = null
)

@Serializable
data class SocketConnectionTelemetryItem(
    val pid: Int,
    val process_name: String,
    val protocol: String = "TCP",
    val local_address: String,
    val local_port: Int,
    val remote_address: String,
    val remote_port: Int,
    val state: String = "ESTABLISHED",
    val observed_at: String? = null
)

// ───────────────────────────── Device Info ──────────────────────────────

@Serializable
data class DeviceInfoTelemetry(
    val manufacturer: String,
    val model: String,
    val device_name: String? = null,
    val android_version: String,
    val sdk_version: Int,
    val build_display: String? = null,
    val build_fingerprint: String? = null,
    val architecture: String = "arm64-v8a",
    val supported_abis: List<String> = emptyList(),
    val kernel_version: String? = null,
    val locale: String? = null,
    val timezone: String? = null,
    val is_emulator: Boolean = false
)

// ───────────────────────────── CPU ──────────────────────────────────────

@Serializable
data class CpuTelemetry(
    val cores: Int,
    val usage_percent: Double? = null,
    val per_core_supported: Boolean = false,
    val per_core_usage: List<Double> = emptyList(),
    val architecture: String = "arm64-v8a",
    val cpu_frequency_mhz: Long? = null,
    val max_frequency_mhz: Long? = null,
    val min_frequency_mhz: Long? = null,
    val thermal_status: String? = null,
    val is_throttled: Boolean? = null
)

// ───────────────────────────── Memory ───────────────────────────────────

@Serializable
data class MemoryTelemetry(
    val total_bytes: Long,
    val available_bytes: Long,
    val used_bytes: Long,
    val usage_percent: Double? = null,
    val low_memory: Boolean = false,
    val threshold_bytes: Long? = null,
    val process_pss_kb: Int? = null,
    val process_private_dirty_kb: Int? = null
)

// ───────────────────────────── Storage ──────────────────────────────────

@Serializable
data class StorageTelemetry(
    val total_bytes: Long,
    val available_bytes: Long,
    val used_bytes: Long,
    val usage_percent: Double? = null,
    val external_total_bytes: Long? = null,
    val external_available_bytes: Long? = null,
    val external_used_bytes: Long? = null
)

// ───────────────────────────── Battery ──────────────────────────────────

@Serializable
data class BatteryTelemetry(
    val percentage: Int,
    val charging: Boolean,
    val health: String = "GOOD",
    val temperature_c: Double? = null,
    val charging_type: String? = null,
    val voltage_mv: Int? = null,
    val current_ua: Int? = null,
    val capacity_uah: Int? = null,
    val power_save_mode: Boolean? = null,
    val battery_saver: Boolean? = null
)

// ───────────────────────────── Network ──────────────────────────────────

@Serializable
data class NetworkTelemetry(
    val connection_type: String,
    val local_ip: String? = null,
    @SerialName("interface")
    val interface_name: String? = null,
    val link_speed_kbps: Int? = null,
    val ipv6_address: String? = null,
    val wifi_ssid: String? = null,
    val wifi_bssid: String? = null,
    val gateway: String? = null,
    val dns_servers: List<String>? = null,
    val is_vpn_active: Boolean? = null,
    val is_metered: Boolean? = null,
    val network_transport: String? = null,
    val bytes_received: Long? = null,
    val bytes_transmitted: Long? = null,
    val mobile_bytes_received: Long? = null,
    val mobile_bytes_transmitted: Long? = null
)

// ───────────────────────────── Security ─────────────────────────────────

@Serializable
data class SecurityPostureTelemetry(
    val screen_lock: Boolean,
    val encryption: String = "ENCRYPTED",
    val developer_options: Boolean,
    val usb_debugging: Boolean,
    val verified_boot: String = "release-keys",
    val security_patch: String? = null,
    val biometric_capability: String = "AVAILABLE",
    val root_detected: Boolean = false,
    val root_assessment: String = "NOT_DETECTED",
    val is_emulator: Boolean = false,
    val unknown_sources_enabled: Boolean? = null,
    val accessibility_services_active: Boolean? = null,
    val device_admin_active: Boolean? = null,
    val play_protect_enabled: Boolean? = null
)

// ───────────────────────────── Applications ────────────────────────────

@Serializable
data class AppTelemetryItem(
    val package_name: String,
    val label: String,
    val version_name: String? = null,
    val version_code: Long? = null,
    val classification: String = "USER_APP",
    val is_enabled: Boolean = true,
    val first_install_time: String? = null,
    val last_update_time: String? = null,
    val requested_permissions: List<String>? = null,
    val signing_sha256: String? = null
)

// ───────────────────────────── Uptime ───────────────────────────────────

@Serializable
data class UptimeTelemetry(
    val uptime_seconds: Long,
    val boot_timestamp: String? = null,
    val last_heartbeat: String? = null,
    val heartbeat_interval_seconds: Int = 20,
    val agent_service_running: Boolean = false,
    val last_telemetry_upload: String? = null,
    val offline_duration_seconds: Long? = null
)

// ───────────────────────────── Foreground App ──────────────────────────

@Serializable
data class ForegroundAppTelemetry(
    val package_name: String? = null,
    val app_name: String? = null,
    val foreground_since: String? = null,
    val usage_duration_seconds: Long? = null,
    val capability_status: String = "SUPPORTED"
)

// ───────────────────────────── Browser Visibility ──────────────────────

@Serializable
data class BrowserVisibility(
    val installed_browsers: List<String> = emptyList(),
    val chrome_detected: Boolean = false,
    val foreground_browser: String? = null,
    val foreground_state: String? = null,
    val tab_visibility_capability: String = "PLATFORM_RESTRICTED",
    val history_capability: String = "PLATFORM_RESTRICTED",
    val note: String = "Android sandboxing prevents cross-app browser tab/history access"
)

// ───────────────────────────── Network Flow ────────────────────────────

@Serializable
data class NetworkFlowItem(
    val destination_ip: String,
    val destination_port: Int? = null,
    val protocol: String? = null,
    val packet_count: Int = 0,
    val bytes_total: Long = 0L,
    val first_seen: String? = null,
    val last_seen: String? = null,
    val dns_name: String? = null
)

// ───────────────────────────── Capability Matrix ──────────────────────

@Serializable
data class CapabilityStatusItem(
    val capability: String,
    val status: String,
    val detail: String? = null
)

// ───────────────────────────── Telemetry Batch ─────────────────────────

@Serializable
data class EndpointTelemetryBatch(
    val agent_id: String,
    val device_id: String,
    val timestamp: String,
    val hostname: String? = null,
    val os_name: String? = "android",
    val os_version: String? = null,
    // Existing endpoint fields (backward-compatible with Windows/macOS)
    val endpoint_processes: List<ProcessTelemetryItem> = emptyList(),
    val active_apps: List<String> = emptyList(),
    val installed_software: List<SoftwareTelemetryItem> = emptyList(),
    val services: List<ServiceTelemetryItem> = emptyList(),
    val listening_ports: List<ListeningPortTelemetryItem> = emptyList(),
    val process_connections: List<SocketConnectionTelemetryItem> = emptyList(),
    val installed_browsers: List<String> = emptyList(),
    val os_info: String? = null,
    // Android extended platform telemetry
    val device_model: String? = null,
    val manufacturer: String? = null,
    val sdk_version: Int? = null,
    val cpu_info: CpuTelemetry? = null,
    val memory_info: MemoryTelemetry? = null,
    val storage_info: StorageTelemetry? = null,
    val battery_info: BatteryTelemetry? = null,
    val network_info: NetworkTelemetry? = null,
    val security_posture: SecurityPostureTelemetry? = null,
    val applications: List<AppTelemetryItem> = emptyList(),
    // NEW: Expanded Android telemetry (all optional for backward compat)
    val device_info: DeviceInfoTelemetry? = null,
    val uptime_info: UptimeTelemetry? = null,
    val foreground_app: ForegroundAppTelemetry? = null,
    val browser_visibility: BrowserVisibility? = null,
    val network_flows: List<NetworkFlowItem> = emptyList(),
    val capability_status: List<CapabilityStatusItem> = emptyList()
)

@Serializable
data class EndpointTelemetrySubmitResponse(
    val success: Boolean,
    val message: String,
    val accepted_at: String,
    val processes_count: Int,
    val software_count: Int,
    val services_count: Int,
    val ports_count: Int
)
