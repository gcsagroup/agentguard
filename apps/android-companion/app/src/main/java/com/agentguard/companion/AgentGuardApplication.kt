package com.agentguard.companion

import android.app.Application
import android.content.Context

class AgentGuardApplication : Application() {
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(LocaleController.wrap(base))
    }
}
