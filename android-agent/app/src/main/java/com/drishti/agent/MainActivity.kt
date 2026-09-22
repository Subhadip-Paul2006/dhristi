package com.drishti.agent

import android.Manifest
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.drishti.agent.collectors.DeviceInfoCollector
import com.drishti.agent.collectors.SecurityCollector
import com.drishti.agent.databinding.ActivityMainBinding
import com.drishti.agent.pairing.PairingUiState
import com.drishti.agent.permissions.PermissionManager
import com.drishti.agent.services.DrishtiVpnService
import com.drishti.agent.services.EndpointForegroundService
import com.drishti.agent.transport.HeartbeatState
import kotlinx.coroutines.launch
import java.time.format.DateTimeFormatter

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val app by lazy { application as DrishtiApplication }

    private var isServiceActive = false

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            Toast.makeText(this, "Notification permission granted", Toast.LENGTH_SHORT).show()
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            DrishtiVpnService.start(this)
            binding.btnToggleVpn.text = "Disable"
            Toast.makeText(this, "Defensive network shield activated", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "VPN authorization denied", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupDeviceInfo()
        setupServerUrlConfig()
        setupPairingControls()
        setupServiceControls()
        setupDefensiveShield()
        requestEssentialPermissions()
        observeAgentState()
    }

    private fun setupDeviceInfo() {
        val devInfo = DeviceInfoCollector(this).collect()
        binding.tvDeviceSubtitle.text = "Android ${devInfo.androidVersion} (API ${devInfo.sdkVersion}) • ${devInfo.manufacturer} ${devInfo.model}"

        val securityInfo = SecurityCollector(this).collect()
        if (securityInfo.root_detected) {
            binding.tvRootStatus.text = "ROOT DETECTED"
            binding.tvRootStatus.setTextColor(Color.parseColor("#EF4444"))
        } else {
            binding.tvRootStatus.text = "VERIFIED CLEAN"
            binding.tvRootStatus.setTextColor(Color.parseColor("#10B981"))
        }
        binding.tvSelinuxStatus.text = "UNKNOWN"
        binding.tvSelinuxStatus.setTextColor(Color.parseColor("#94A3B8"))
    }

    private fun setupServerUrlConfig() {
        binding.etServerUrl.setText(app.secureStorage.getServerUrl())
        binding.btnSaveServerUrl.setOnClickListener {
            val url = binding.etServerUrl.text.toString().trim()
            if (url.isNotEmpty()) {
                app.secureStorage.setServerUrl(url)
                Toast.makeText(this, "Server URL updated", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun setupPairingControls() {
        binding.btnInitiatePairing.setOnClickListener {
            app.pairingManager.initiatePairing()
        }

        binding.btnForceRepair.setOnClickListener {
            app.pairingManager.forceRePair()
        }
    }

    private fun setupServiceControls() {
        binding.btnToggleService.setOnClickListener {
            if (isServiceActive) {
                EndpointForegroundService.stop(this)
                binding.btnToggleService.text = "Start Service"
                isServiceActive = false
            } else {
                EndpointForegroundService.start(this)
                binding.btnToggleService.text = "Stop Service"
                isServiceActive = true
            }
        }

        binding.btnSendTelemetryNow.setOnClickListener {
            lifecycleScope.launch {
                val success = app.telemetryManager.collectAndSend()
                if (success) {
                    Toast.makeText(this@MainActivity, "Telemetry transmitted successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, "Telemetry send failed (check server connection/pairing)", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun setupDefensiveShield() {
        binding.btnToggleVpn.setOnClickListener {
            if (DrishtiVpnService.isRunning.get()) {
                DrishtiVpnService.stop(this)
                binding.btnToggleVpn.text = "Enable"
            } else {
                val prepareIntent = PermissionManager.prepareVpnIntent(this)
                if (prepareIntent != null) {
                    vpnPermissionLauncher.launch(prepareIntent)
                } else {
                    DrishtiVpnService.start(this)
                    binding.btnToggleVpn.text = "Disable"
                }
            }
        }

        binding.btnGrantUsageStats.setOnClickListener {
            if (PermissionManager.hasUsageStatsPermission(this)) {
                Toast.makeText(this, "Usage access already granted", Toast.LENGTH_SHORT).show()
            } else {
                startActivity(PermissionManager.createUsageStatsSettingsIntent())
            }
        }
    }

    private fun requestEssentialPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (!PermissionManager.hasNotificationPermission(this)) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun observeAgentState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    app.pairingManager.uiState.collect { state ->
                        updatePairingUi(state)
                    }
                }

                launch {
                    app.heartbeatManager.state.collect { state ->
                        updateHeartbeatBadge(state)
                    }
                }

                launch {
                    app.heartbeatManager.lastSuccessfulHeartbeat.collect { instant ->
                        binding.tvLastHeartbeat.text = if (instant != null) {
                            "Last Heartbeat: ${DateTimeFormatter.ISO_INSTANT.format(instant)}"
                        } else {
                            "Last Heartbeat: Never"
                        }
                    }
                }

                launch {
                    app.telemetryManager.lastTelemetrySent.collect { instant ->
                        binding.tvLastTelemetry.text = if (instant != null) {
                            "Last Telemetry Sent: ${DateTimeFormatter.ISO_INSTANT.format(instant)}"
                        } else {
                            "Last Telemetry Sent: Never"
                        }
                    }
                }
            }
        }
    }

    private fun updatePairingUi(state: PairingUiState) {
        when (state) {
            is PairingUiState.Unpaired -> {
                binding.layoutUnpaired.visibility = View.VISIBLE
                binding.layoutPairingInProgress.visibility = View.GONE
                binding.layoutPaired.visibility = View.GONE
            }
            is PairingUiState.Initializing -> {
                binding.layoutUnpaired.visibility = View.GONE
                binding.layoutPairingInProgress.visibility = View.VISIBLE
                binding.tvPairingCode.text = "..."
                binding.tvPairingCountdown.text = "Connecting to Drishti SOC..."
                binding.layoutPaired.visibility = View.GONE
            }
            is PairingUiState.WaitingForOperator -> {
                binding.layoutUnpaired.visibility = View.GONE
                binding.layoutPairingInProgress.visibility = View.VISIBLE
                binding.tvPairingCode.text = state.pairingCode
                binding.tvPairingCountdown.text = "Session: ${state.sessionId.take(8)}... (Awaiting approval)"
                binding.layoutPaired.visibility = View.GONE
            }
            is PairingUiState.Connecting -> {
                binding.layoutUnpaired.visibility = View.GONE
                binding.layoutPairingInProgress.visibility = View.VISIBLE
                binding.tvPairingCountdown.text = "Finalizing pairing with Drishti SOC..."
                binding.layoutPaired.visibility = View.GONE
            }
            is PairingUiState.Paired, is PairingUiState.Connected -> {
                binding.layoutUnpaired.visibility = View.GONE
                binding.layoutPairingInProgress.visibility = View.GONE
                binding.layoutPaired.visibility = View.VISIBLE
                binding.tvAgentId.text = app.secureStorage.getAgentId() ?: "Unknown"

                // Auto-start foreground service upon successful pairing if not yet active
                if (!isServiceActive) {
                    EndpointForegroundService.start(this)
                    binding.btnToggleService.text = "Stop Service"
                    isServiceActive = true
                }
            }
            is PairingUiState.Offline -> {
                binding.layoutUnpaired.visibility = View.GONE
                binding.layoutPairingInProgress.visibility = View.GONE
                binding.layoutPaired.visibility = View.VISIBLE
                binding.tvAgentId.text = app.secureStorage.getAgentId() ?: "Unknown"
            }
            is PairingUiState.Expired -> {
                binding.layoutUnpaired.visibility = View.VISIBLE
                binding.layoutPairingInProgress.visibility = View.GONE
                binding.layoutPaired.visibility = View.GONE
                Toast.makeText(this, state.reason, Toast.LENGTH_LONG).show()
            }
            is PairingUiState.Error -> {
                binding.layoutUnpaired.visibility = View.VISIBLE
                binding.layoutPairingInProgress.visibility = View.GONE
                binding.layoutPaired.visibility = View.GONE
                Toast.makeText(this, "Pairing error: ${state.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun updateHeartbeatBadge(state: HeartbeatState) {
        binding.tvStatusBadge.text = state.name
        when (state) {
            HeartbeatState.ONLINE -> {
                binding.tvStatusBadge.setBackgroundColor(Color.parseColor("#10B981"))
                binding.tvStatusBadge.setTextColor(Color.WHITE)
            }
            HeartbeatState.SENDING -> {
                binding.tvStatusBadge.setBackgroundColor(Color.parseColor("#0EA5E9"))
                binding.tvStatusBadge.setTextColor(Color.WHITE)
            }
            HeartbeatState.STALE -> {
                binding.tvStatusBadge.setBackgroundColor(Color.parseColor("#F59E0B"))
                binding.tvStatusBadge.setTextColor(Color.BLACK)
            }
            HeartbeatState.OFFLINE, HeartbeatState.UNAUTHORIZED -> {
                binding.tvStatusBadge.setBackgroundColor(Color.parseColor("#EF4444"))
                binding.tvStatusBadge.setTextColor(Color.WHITE)
            }
            HeartbeatState.IDLE -> {
                binding.tvStatusBadge.setBackgroundColor(Color.parseColor("#1E293B"))
                binding.tvStatusBadge.setTextColor(Color.parseColor("#94A3B8"))
            }
        }
    }
}
