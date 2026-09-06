package com.agentguard.companion

import org.junit.Assert.assertTrue
import org.junit.Test

class RelayBuildPolicyTest {
    @Test
    fun `debug build keeps relay available for protocol development`() {
        assertTrue(RelayClient.isAvailable())
    }
}
