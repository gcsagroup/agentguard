package com.agentguard.companion

import org.junit.Assert.assertFalse
import org.junit.Test

class RelayBuildPolicyTest {
    @Test
    fun `release build cannot enable unauthenticated relay v1`() {
        assertFalse(RelayClient.isAvailable())
    }
}
