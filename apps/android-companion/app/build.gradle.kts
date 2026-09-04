plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.agentguard.companion"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.agentguard.companion"
        minSdk = 26
        targetSdk = 36
        versionCode = 1000001
        versionName = "1.0.0-rc.1"
    }

    signingConfigs {
        create("release") {
            val store = System.getenv("AGENTGUARD_STORE_FILE")
                ?: (project.findProperty("AGENTGUARD_STORE_FILE") as String?)
            if (store != null) {
                storeFile = file(store)
                storePassword = System.getenv("AGENTGUARD_STORE_PASSWORD")
                    ?: (project.findProperty("AGENTGUARD_STORE_PASSWORD") as String?)
                keyAlias = System.getenv("AGENTGUARD_KEY_ALIAS")
                    ?: (project.findProperty("AGENTGUARD_KEY_ALIAS") as String?)
                    ?: "agentguard"
                keyPassword = System.getenv("AGENTGUARD_KEY_PASSWORD")
                    ?: (project.findProperty("AGENTGUARD_KEY_PASSWORD") as String?)
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    bundle {
        language {
            // 运行时切换语言(LocaleController)而不接 Play Core 的按需语言下载:
            // 关掉语言拆分,三语资源全部随基础 APK 走(lint AppBundleLocaleChanges,真机报告 P2-2)。
            enableSplit = false
        }
    }

    lint {
        // 真机报告 P2-2:14 条 lint warning 清零之后,warning 就是 error——再冒出一条就红,
        // 不再靠人去读 HTML 报告。`make check-android` 与 CI 的 android job 都跑 lintDebug。
        warningsAsErrors = true
        abortOnError = true
        // 三条"有更新版本可用"的检查刻意关掉:它们查的是**网络上**此刻有什么,别人发一个新版本
        // 这里就红——那不是本仓库的状态,而且离线(--offline / 最小容器)跑法根本查不到。
        // 依赖版本由 lockfile 与 cargo-deny/gradle 的显式钉住管;升级是一次有人点头的提交,不是 lint 的事。
        disable += setOf("AndroidGradlePluginVersion", "GradleDependency", "NewerVersionAvailable")
    }

    testOptions {
        unitTests {
            // The Kotlin half of this companion had no test target at all, which is why four
            // event serializers could sit with no callers and a normative hash could sit
            // unverified against the Rust one.
            isReturnDefaultValues = true
            // 真机报告 P2-2 的残余:"补 instrumented / Compose / AccessibilityService 测试"。
            // 设备测试在 CI 里跑不了(也没有 /dev/kvm 起模拟器),但 Robolectric 能在 JVM 上跑
            // **真的 Android 框架**:界面能渲染、AccessibilityEvent 不再是 `Stub!`。
            // 打开资源是 Robolectric 的前提(它要 merged manifest 与 res/),对既有的纯函数测试无影响。
            isIncludeAndroidResources = true
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // `org.json` is part of android.jar, where every method throws `Stub!` under a JVM unit
    // test. A real implementation on the test classpath is what lets PayloadSerializer and
    // RelayClient.parseVerdicts be tested without a device.
    testImplementation("org.json:json:20240303")
    testImplementation("junit:junit:4.13.2")
    // JVM 上跑真 Android 框架(见 testOptions 的注释)。**不是**设备测试的替代品:
    // Robolectric 用的是自己的 android-all 实现,真机的 OEM 行为、TalkBack、前台服务限制
    // 仍然只有设备能验 —— docs/acceptance-runbook.md §5 与 android-e2e.sh 才是那一层。
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core-ktx:1.6.1")
    testImplementation("androidx.compose.ui:ui-test-junit4:1.6.8")
    debugImplementation("androidx.compose.ui:ui-test-manifest:1.6.8")
}
