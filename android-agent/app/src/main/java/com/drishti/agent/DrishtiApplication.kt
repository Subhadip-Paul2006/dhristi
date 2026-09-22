package com.drishti.agent

import android.app.Application
import com.drishti.agent.collectors.DeviceInfoCollector
import com.drishti.agent.models.EndpointIdentity
import com.drishti.agent.pairing.PairingManager
import com.drishti.agent.storage.SecureStorage
import com.drishti.agent.transport.DrishtiApiClient
import com.drishti.agent.transport.HeartbeatManager
import com.drishti.agent.transport.TelemetryManager

class DrishtiApplication : Application() {

    lateinit var secureStorage: SecureStorage
        private set

    lateinit var apiClient: DrishtiApiClient
        private set

    lateinit var pairingManager: PairingManager
        private set

    lateinit var heartbeatManager: HeartbeatManager
        private set

    lateinit var telemetryManager: TelemetryManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        secureStorage = SecureStorage(this)
        apiClient = DrishtiApiClient(baseUrlProvider = { secureStorage.getServerUrl() })

        val identityProvider: () -> EndpointIdentity = {
            val devInfo = DeviceInfoCollector(this).collect()
            secureStorage.getOrCreateIdentity(
                hostname = devInfo.deviceName,
                osVersion = devInfo.androidVersion,
                manufacturer = devInfo.manufacturer,
                model = devInfo.model,
                sdkVersion = devInfo.sdkVersion
            )
        }

        pairingManager = PairingManager(
            apiClient = apiClient,
            secureStorage = secureStorage,
            identityProvider = identityProvider
        )

        heartbeatManager = HeartbeatManager(
            apiClient = apiClient,
            secureStorage = secureStorage,
            identityProvider = identityProvider
        )

        telemetryManager = TelemetryManager(
            context = this,
            apiClient = apiClient,
            secureStorage = secureStorage,
            identityProvider = identityProvider
        )
    }

    companion object {
        lateinit var instance: DrishtiApplication
            private set
    }
}
