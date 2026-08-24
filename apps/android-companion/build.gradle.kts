plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
    // Kotlin 2.0 moved the Compose compiler into the Kotlin repo: it is versioned
    // with Kotlin and applied as a plugin. The old
    // `composeOptions { kotlinCompilerExtensionVersion = ... }` route pins a
    // Kotlin version (1.5.14 ⇒ Kotlin 1.9.24) and fails the build on 2.0.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.0" apply false
}
