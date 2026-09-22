package com.drishti.agent.collectors

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.wifi.WifiManager
import android.os.Build
import com.drishti.agent.models.NetworkTelemetry
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

class NetworkCollector(private val context: Context) {

    fun collect(): NetworkTelemetry {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        var connectionType = "NONE"
        var linkSpeedKbps: Int? = null
        var isVpnActive: Boolean? = null
        var isMetered: Boolean? = null
        var networkTransport: String? = null
        var dnsServers: List<String>? = null
        var gateway: String? = null

        if (cm != null) {
            val activeNetwork = cm.activeNetwork
            val caps = cm.getNetworkCapabilities(activeNetwork)
            val linkProps = cm.getLinkProperties(activeNetwork)

            if (caps != null) {
                // Determine primary transport
                connectionType = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WI-FI"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "BLUETOOTH"
                    else -> "OTHER"
                }

                networkTransport = connectionType

                val downstream = caps.linkDownstreamBandwidthKbps
                if (downstream > 0) {
                    linkSpeedKbps = downstream
                }

                isVpnActive = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                isMetered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }

            // DNS and gateway from LinkProperties
            if (linkProps != null) {
                dnsServers = linkProps.dnsServers?.mapNotNull { it.hostAddress }?.ifEmpty { null }

                val routes = linkProps.routes
                gateway = routes.firstOrNull { it.isDefaultRoute }?.gateway?.hostAddress
            }
        }

        val (localIp, ifaceName, ipv6Address) = getActiveNetworkAddresses()

        // Wi-Fi SSID/BSSID — requires ACCESS_FINE_LOCATION on Android 8.1+
        // We attempt but gracefully degrade
        val (wifiSsid, wifiBssid) = getWifiDetails()

        // Traffic statistics (cumulative since boot)
        val bytesRx = try { TrafficStats.getTotalRxBytes().let { if (it >= 0) it else null } } catch (_: Exception) { null }
        val bytesTx = try { TrafficStats.getTotalTxBytes().let { if (it >= 0) it else null } } catch (_: Exception) { null }
        val mobileRx = try { TrafficStats.getMobileRxBytes().let { if (it >= 0) it else null } } catch (_: Exception) { null }
        val mobileTx = try { TrafficStats.getMobileTxBytes().let { if (it >= 0) it else null } } catch (_: Exception) { null }

        return NetworkTelemetry(
            connection_type = connectionType,
            local_ip = localIp,
            interface_name = ifaceName,
            link_speed_kbps = linkSpeedKbps,
            ipv6_address = ipv6Address,
            wifi_ssid = wifiSsid,
            wifi_bssid = wifiBssid,
            gateway = gateway,
            dns_servers = dnsServers,
            is_vpn_active = isVpnActive,
            is_metered = isMetered,
            network_transport = networkTransport,
            bytes_received = bytesRx,
            bytes_transmitted = bytesTx,
            mobile_bytes_received = mobileRx,
            mobile_bytes_transmitted = mobileTx
        )
    }

    /**
     * Returns (localIpv4, interfaceName, ipv6Address).
     */
    private fun getActiveNetworkAddresses(): Triple<String?, String?, String?> {
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return Triple(null, null, null)
            var ipv4: String? = null
            var ipv6: String? = null
            var ifName: String? = null

            for (iface in interfaces) {
                if (iface.isLoopback || !iface.isUp) continue

                val addrs = iface.inetAddresses
                for (addr in addrs) {
                    if (addr.isLoopbackAddress) continue

                    when (addr) {
                        is Inet4Address -> {
                            val hostAddr = addr.hostAddress
                            if (!hostAddr.isNullOrBlank() && !hostAddr.startsWith("127.")) {
                                if (ipv4 == null) {
                                    ipv4 = hostAddr
                                    ifName = iface.name
                                }
                            }
                        }
                        is Inet6Address -> {
                            val hostAddr = addr.hostAddress
                            if (!hostAddr.isNullOrBlank() && !addr.isLinkLocalAddress) {
                                if (ipv6 == null) {
                                    ipv6 = hostAddr
                                    if (ifName == null) ifName = iface.name
                                }
                            }
                        }
                    }
                }
            }
            return Triple(ipv4, ifName, ipv6)
        } catch (_: Exception) {
        }
        return Triple(null, null, null)
    }

    /**
     * Attempts to read Wi-Fi SSID and BSSID.
     * Returns ("unknown ssid", null) when location permission is not granted.
     */
    @Suppress("DEPRECATION")
    private fun getWifiDetails(): Pair<String?, String?> {
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
                ?: return Pair(null, null)

            if (!wm.isWifiEnabled) return Pair(null, null)

            val info = wm.connectionInfo ?: return Pair(null, null)

            val ssid = info.ssid?.let {
                val cleaned = it.trim('"')
                if (cleaned == "<unknown ssid>" || cleaned.isBlank()) null else cleaned
            }
            val bssid = info.bssid?.let {
                if (it == "02:00:00:00:00:00" || it.isBlank()) null else it
            }

            Pair(ssid, bssid)
        } catch (_: Exception) {
            Pair(null, null)
        }
    }
}
