package com.drishti.agent.services

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.drishti.agent.MainActivity
import com.drishti.agent.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import com.drishti.agent.models.NetworkFlowItem
import java.io.FileInputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * DrishtiVpnService provides optional, user-consented defensive destination tracking.
 *
 * Privacy & Security Guarantees:
 * - NO payload inspection or deep packet storage.
 * - Only records destination IP and port metadata for anomalous outbound connection alerts.
 * - Operates entirely locally on-device without remote VPN proxying.
 */
class DrishtiVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private var workerJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == ACTION_STOP) {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning.get()) return

        try {
            val builder = Builder()
                .setSession("Drishti Defensive Shield")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .setMtu(1500)
                .setBlocking(false)

            // CRITICAL: Exclude Drishti's own package from VPN to prevent black-holing
            // the agent's heartbeat and telemetry traffic to the backend SOC.
            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to exclude own package from VPN: ${e.message}")
            }

            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                isRunning.set(true)

                val notification = createNotification()
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    startForeground(
                        NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    )
                } else {
                    startForeground(NOTIFICATION_ID, notification)
                }

                startPacketMonitoring(vpnInterface!!)
                Log.i(TAG, "Drishti Defensive VPN monitoring started successfully")
            } else {
                Log.w(TAG, "VPN builder returned null interface (permission not granted or revoked)")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start defensive VPN service", e)
            stopSelf()
        }
    }

    private fun startPacketMonitoring(pfd: ParcelFileDescriptor) {
        workerJob = scope.launch {
            val inputStream = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteBuffer.allocate(16384)

            try {
                while (isActive && isRunning.get()) {
                    val length = inputStream.read(buffer.array())
                    if (length > 0) {
                        // Extract IP header destination metadata defensively (IPv4 version = 4)
                        val versionAndIhl = buffer.get(0).toInt() and 0xFF
                        val version = versionAndIhl shr 4
                        val ihl = (versionAndIhl and 0x0F) * 4
                        if (version == 4 && length >= 20) {
                            val protocolNum = buffer.get(9).toInt() and 0xFF
                            val protocolStr = when (protocolNum) {
                                6 -> "TCP"
                                17 -> "UDP"
                                1 -> "ICMP"
                                else -> "IP($protocolNum)"
                            }

                            val destIpBytes = ByteArray(4)
                            buffer.position(16)
                            buffer.get(destIpBytes)
                            val destIp = InetAddress.getByAddress(destIpBytes).hostAddress ?: ""

                            var destPort: Int? = null
                            if ((protocolNum == 6 || protocolNum == 17) && length >= ihl + 4) {
                                destPort = ((buffer.get(ihl + 2).toInt() and 0xFF) shl 8) or
                                        (buffer.get(ihl + 3).toInt() and 0xFF)
                            }

                            if (destIp.isNotEmpty()) {
                                destinationCounter.compute(destIp) { _, count -> (count ?: 0) + 1 }
                                recordFlow(destIp, destPort, protocolStr, length.toLong())
                            }
                        }
                    }
                    buffer.clear()
                }
            } catch (e: Exception) {
                if (isActive) {
                    Log.w(TAG, "Defensive packet monitor error: ${e.message}")
                }
            }
        }
    }

    private fun stopVpn() {
        isRunning.set(false)
        workerJob?.cancel()
        try {
            vpnInterface?.close()
        } catch (ignored: Exception) {}
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.i(TAG, "Drishti Defensive VPN stopped")
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Drishti Network Monitor",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors network destinations for defensive security"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, DrishtiVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Drishti Network Shield Active")
            .setContentText("Defensive destination analysis active")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop Shield", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        private const val TAG = "DrishtiVpnService"
        const val CHANNEL_ID = "drishti_vpn_channel"
        const val NOTIFICATION_ID = 1002
        const val ACTION_START = "com.drishti.agent.action.START_VPN"
        const val ACTION_STOP = "com.drishti.agent.action.STOP_VPN"

        val isRunning = AtomicBoolean(false)
        val destinationCounter = ConcurrentHashMap<String, Int>()

        data class FlowMetadata(
            val destIp: String,
            val destPort: Int?,
            val protocol: String,
            var packetCount: Int,
            var byteCount: Long,
            val firstSeen: String,
            var lastSeen: String
        )

        private val flowMap = ConcurrentHashMap<String, FlowMetadata>()

        fun recordFlow(destIp: String, destPort: Int?, protocol: String, bytes: Long) {
            val key = "$destIp:${destPort ?: 0}:$protocol"
            val nowIso = Instant.now().toString()
            flowMap.compute(key) { _, existing ->
                if (existing == null) {
                    FlowMetadata(
                        destIp = destIp,
                        destPort = destPort,
                        protocol = protocol,
                        packetCount = 1,
                        byteCount = bytes,
                        firstSeen = nowIso,
                        lastSeen = nowIso
                    )
                } else {
                    existing.packetCount += 1
                    existing.byteCount += bytes
                    existing.lastSeen = nowIso
                    existing
                }
            }
        }

        fun getRecentFlows(): List<NetworkFlowItem> {
            return flowMap.values.map { flow ->
                NetworkFlowItem(
                    destination_ip = flow.destIp,
                    destination_port = flow.destPort,
                    protocol = flow.protocol,
                    packet_count = flow.packetCount,
                    bytes_total = flow.byteCount,
                    first_seen = flow.firstSeen,
                    last_seen = flow.lastSeen
                )
            }.sortedByDescending { it.bytes_total }.take(50)
        }

        fun start(context: Context) {
            val intent = Intent(context, DrishtiVpnService::class.java).apply {
                action = ACTION_START
            }
            context.startService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, DrishtiVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
