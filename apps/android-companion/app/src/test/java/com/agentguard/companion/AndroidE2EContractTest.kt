package com.agentguard.companion

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 防止设备验收脚本再次与 SessionState 的持久化合同分叉。 */
class AndroidE2EContractTest {
    private val script = locateRepoRoot().resolve("scripts/acceptance/android-e2e.sh")

    @Test
    fun `device acceptance script parses and uses the fail closed restart contract`() {
        val syntax = ProcessBuilder("bash", "-n", script.absolutePath)
            .redirectErrorStream(true)
            .start()
        val output = syntax.inputStream.bufferedReader().use { it.readText() }
        assertEquals(output, 0, syntax.waitFor())

        val source = script.readText()
        assertTrue(
            source.contains(
                "if printf '%s' \"\$P\" | grep -q 'name=\"session_requested\" value=\"true\"'; " +
                    "then STARTED=1; break; fi",
            ),
        )
        assertFalse(
            source.contains(
                "if printf '%s' \"\$P\" | grep -q 'name=\"session_active\" value=\"true\"'; " +
                    "then STARTED=1; break; fi",
            ),
        )
        assertTrue(source.contains("restarted fail-closed; session inactive"))
        assertTrue(source.contains("ongoing session notification (id 1001) present"))
        assertFalse(source.contains("foreground notification (id 1001) present"))
        assertFalse(source.contains("session_active 仍为 true"))
    }

    private fun locateRepoRoot(): File {
        var current = File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        while (true) {
            val candidate = current.resolve("scripts/acceptance/android-e2e.sh")
            if (candidate.isFile) return current
            current = current.parentFile ?: error("找不到 AgentGuard 仓库根目录")
        }
    }
}
