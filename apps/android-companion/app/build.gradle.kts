plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.agentguard.companion"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.agentguard.companion"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
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

    testOptions {
        unitTests {
            // The Kotlin half of this companion had no test target at all, which is why four
            // event serializers could sit with no callers and a normative hash could sit
            // unverified against the Rust one. `isIncludeAndroidResources` is off: these are
            // pure-JVM tests over pure functions, deliberately — a test that needs a device is
            // a test that will not run in CI.
            isReturnDefaultValues = true
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
}
