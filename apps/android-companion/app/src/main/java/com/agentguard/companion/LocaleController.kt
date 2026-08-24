package com.agentguard.companion

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

object LocaleController {
    private const val PREFS = "agentguard"
    private const val KEY = "locale_mode"
    const val SYSTEM = "system"
    const val ENGLISH = "en"
    const val SIMPLIFIED_CHINESE = "zh-Hans"
    const val TRADITIONAL_CHINESE = "zh-Hant"

    val modes = listOf(SYSTEM, ENGLISH, SIMPLIFIED_CHINESE, TRADITIONAL_CHINESE)

    fun mode(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, SYSTEM) ?: SYSTEM

    fun setMode(context: Context, mode: String) {
        require(mode in modes)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY, mode)
            .apply()
    }

    fun wrap(base: Context): Context {
        val locale = when (mode(base)) {
            ENGLISH -> Locale.ENGLISH
            SIMPLIFIED_CHINESE -> Locale.SIMPLIFIED_CHINESE
            TRADITIONAL_CHINESE -> Locale.TRADITIONAL_CHINESE
            else -> return base
        }
        val configuration = Configuration(base.resources.configuration)
        configuration.setLocale(locale)
        configuration.setLayoutDirection(locale)
        return base.createConfigurationContext(configuration)
    }

    fun text(context: Context, resourceId: Int, vararg args: Any): String =
        wrap(context).getString(resourceId, *args)
}
