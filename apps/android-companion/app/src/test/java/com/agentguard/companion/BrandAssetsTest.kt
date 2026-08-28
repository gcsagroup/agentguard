package com.agentguard.companion

import java.io.File
import java.io.DataInputStream
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrandAssetsTest {
    private val moduleRoot: File = locateModuleRoot()

    @Test
    fun `启动和通知图标覆盖全部密度且尺寸正确`() {
        val densities = linkedMapOf(
            "mdpi" to Triple(48, 108, 24),
            "hdpi" to Triple(72, 162, 36),
            "xhdpi" to Triple(96, 216, 48),
            "xxhdpi" to Triple(144, 324, 72),
            "xxxhdpi" to Triple(192, 432, 96),
        )

        densities.forEach { (density, sizes) ->
            assertPng("app/src/main/res/mipmap-$density/ic_launcher.png", sizes.first, true)
            assertPng("app/src/main/res/mipmap-$density/ic_launcher_round.png", sizes.first, true)
            assertPng(
                "app/src/main/res/drawable-$density/ic_launcher_foreground.png",
                sizes.second,
                true,
            )
            assertPng(
                "app/src/main/res/drawable-$density/ic_launcher_monochrome.png",
                sizes.second,
                true,
            )
            assertPng(
                "app/src/main/res/drawable-$density/ic_stat_agentguard.png",
                sizes.third,
                true,
            )
        }
    }

    @Test
    fun `清单和通知代码只引用AgentGuard图标`() {
        val manifest = read("app/src/main/AndroidManifest.xml")
        assertTrue(manifest.contains("android:icon=\"@mipmap/ic_launcher\""))
        assertTrue(manifest.contains("android:roundIcon=\"@mipmap/ic_launcher_round\""))

        val foregroundService = read(
            "app/src/main/java/com/agentguard/companion/GuardForegroundService.kt",
        )
        val accessibilityService = read(
            "app/src/main/java/com/agentguard/companion/GuardAccessibilityService.kt",
        )
        listOf(foregroundService, accessibilityService).forEach { source ->
            assertTrue(source.contains("setSmallIcon(R.drawable.ic_stat_agentguard)"))
            assertFalse(source.contains("setSmallIcon(android.R.drawable"))
        }
    }

    @Test
    fun `自适应图标按系统版本隔离单色层`() {
        listOf("ic_launcher.xml", "ic_launcher_round.xml").forEach { name ->
            assertFalse(File(moduleRoot, "app/src/main/res/mipmap-anydpi/$name").exists())

            val v26 = read("app/src/main/res/mipmap-anydpi-v26/$name")
            assertTrue(v26.contains("@drawable/ic_launcher_background"))
            assertTrue(v26.contains("@drawable/ic_launcher_foreground"))
            assertFalse(v26.contains("<monochrome"))

            val v33 = read("app/src/main/res/mipmap-anydpi-v33/$name")
            assertTrue(v33.contains("@drawable/ic_launcher_background"))
            assertTrue(v33.contains("@drawable/ic_launcher_foreground"))
            assertTrue(v33.contains("@drawable/ic_launcher_monochrome"))
        }
    }

    private fun assertPng(relativePath: String, expectedSize: Int, requiresAlpha: Boolean) {
        val file = File(moduleRoot, relativePath)
        assertTrue("缺少资源：$relativePath", file.isFile)
        DataInputStream(file.inputStream().buffered()).use { input ->
            // 直接检查 PNG 的 IHDR，避免给 Android 单元测试引入桌面图像库。
            val signature = ByteArray(8).also(input::readFully)
            assertArrayEquals(
                "PNG 签名错误：$relativePath",
                byteArrayOf(-119, 80, 78, 71, 13, 10, 26, 10),
                signature,
            )
            assertEquals("IHDR 长度错误：$relativePath", 13, input.readInt())
            val chunkType = ByteArray(4).also(input::readFully)
            assertEquals("IHDR", String(chunkType, StandardCharsets.US_ASCII))
            assertEquals("宽度错误：$relativePath", expectedSize, input.readInt())
            assertEquals("高度错误：$relativePath", expectedSize, input.readInt())
            input.readUnsignedByte() // bit depth
            val colorType = input.readUnsignedByte()
            if (requiresAlpha) {
                assertTrue(
                    "缺少 Alpha 通道：$relativePath（PNG color type=$colorType）",
                    colorType == 4 || colorType == 6,
                )
            }
        }
    }

    private fun read(relativePath: String): String = File(moduleRoot, relativePath).readText()

    private fun locateModuleRoot(): File {
        var current = File(requireNotNull(System.getProperty("user.dir"))).canonicalFile
        while (true) {
            if (File(current, "app/src/main/AndroidManifest.xml").isFile) return current
            val nested = File(current, "apps/android-companion")
            if (File(nested, "app/src/main/AndroidManifest.xml").isFile) return nested
            current = current.parentFile ?: error("找不到 Android Companion 模块")
        }
    }
}
