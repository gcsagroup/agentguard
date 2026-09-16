package com.agentguard.companion

import java.io.File
import java.nio.file.Files
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

    @Test
    fun `release invocation stops before adb or evidence mutation`() = withFixture { folder ->
        val evidence = folder.resolve("existing").apply { mkdir() }
        val original = evidence.resolve("e2e-results.tsv").apply { writeText("保留旧证据\n") }
        val result = runScript(folder, "--evidence", evidence.path)
        assertEquals(result.second, 2, result.first)
        assertTrue(result.second.contains("AGENTGUARD_ANDROID_E2E=BLOCKED scope=release"))
        assertEquals("保留旧证据\n", original.readText())
        assertFalse(folder.resolve("adb-calls.txt").exists())
    }

    @Test
    fun `development invocation refuses an existing evidence directory`() = withFixture { folder ->
        val evidence = folder.resolve("existing").apply { mkdir() }
        val original = evidence.resolve("audit-e2e.db").apply { writeText("原数据库") }
        val result = runScript(folder, "--development-relay", "--evidence", evidence.path)
        assertEquals(result.second, 2, result.first)
        assertEquals("原数据库", original.readText())
        assertFalse(evidence.resolve("e2e-results.tsv").exists())
        assertFalse(folder.resolve("adb-calls.txt").exists())
    }

    @Test
    fun `no device cannot remove an unrelated reverse mapping`() = withFixture { folder ->
        val evidence = folder.resolve("new")
        val result = runScript(folder, "--development-relay", "--evidence", evidence.path)
        assertEquals(result.second, 1, result.first)
        assertTrue(result.second.contains("AGENTGUARD_ANDROID_RELAY_DEV=BLOCKED"))
        assertTrue(result.second.contains("AGENTGUARD_ANDROID_E2E=BLOCKED scope=release"))
        assertEquals("devices\n", folder.resolve("adb-calls.txt").readText())
        assertTrue(evidence.resolve("e2e-results.tsv").readText().contains("BLOCKED(no device)"))
    }

    @Test
    fun `even successful development checks cannot emit release pass`() {
        // 执行脚本里的实际结果汇总函数，覆盖成功、阻塞及失败优先级；不伪装成设备验证。
        val function = "finish() {" + script.readText().substringAfter("finish() {").substringBefore("\n}") + "\n}"
        for ((fails, blocks, expected) in listOf(Triple(0, 0, "PASS"), Triple(0, 1, "BLOCKED"), Triple(1, 1, "FAIL"))) {
            val process = ProcessBuilder(
                "bash", "-c",
                "$function\nFAILS=$fails; BLOCKS=$blocks; RESULTS=test; EVIDENCE=test; DEVICE_KIND=real; finish",
            ).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            assertEquals(output, if (expected == "PASS") 0 else 1, process.waitFor())
            assertTrue(output.contains("AGENTGUARD_ANDROID_RELAY_DEV=$expected device=real"))
            assertTrue(output.contains("AGENTGUARD_ANDROID_E2E=BLOCKED scope=release"))
            assertFalse(output.contains("AGENTGUARD_ANDROID_E2E=PASS"))
        }
    }

    private fun withFixture(block: (File) -> Unit) {
        val folder = Files.createTempDirectory("agentguard-android-script-").toFile()
        try {
            val adb = folder.resolve("adb")
            adb.writeText("#!/bin/sh\nprintf '%s\\n' \"\$*\" >> \"\$ANDROID_TEST_ADB_LOG\"\nprintf 'List of devices attached\\n'\n")
            check(adb.setExecutable(true))
            block(folder)
        } finally {
            check(folder.deleteRecursively())
        }
    }

    private fun runScript(folder: File, vararg args: String): Pair<Int, String> {
        val builder = ProcessBuilder(listOf("bash", script.absolutePath) + args).redirectErrorStream(true)
        builder.environment()["PATH"] = folder.path + File.pathSeparator + System.getenv("PATH")
        builder.environment()["ANDROID_TEST_ADB_LOG"] = folder.resolve("adb-calls.txt").path
        val process = builder.start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return process.waitFor() to output
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
