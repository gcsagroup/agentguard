package com.agentguard.companion

import android.Manifest
import android.content.Intent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    /**
     * Runtime request for `POST_NOTIFICATIONS`.
     *
     * The permission was declared in the manifest and **never requested**, which on API 33+
     * means it is never granted. Notifications are the only channel by which a required
     * confirmation reaches the user on the phone, so an unrequested permission turned Aura's
     * Critical Node gate into a line in a log file. Declaring a permission is not holding it.
     */
    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            notificationsGranted = granted
        }

    /** Whether confirmations can actually reach the user. Surfaced in the UI, not assumed. */
    private var notificationsGranted: Boolean = true

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            notificationsGranted = true
            return
        }
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        notificationsGranted = granted
        if (!granted) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Ask before the first session, not on first risk: the permission is what makes a
        // confirmation reachable, and finding out it is missing at the moment a payment needs
        // approving is finding out too late.
        ensureNotificationPermission()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    // P1-6:进程重建后先读回落盘的会话状态,再决定界面显示什么。
                    remember { SessionState.restore(this@MainActivity) }
                    var sessionActive by remember { mutableStateOf(SessionState.active) }
                    var sessionId by remember { mutableStateOf(SessionState.sessionId) }
                    var lastRisk by remember {
                        mutableStateOf(EnvelopeSink.lastRiskJson(this@MainActivity))
                    }
                    var envelopePath by remember {
                        mutableStateOf(EnvelopeSink.lastEnvelopePath(this@MainActivity))
                    }
                    var envSummary by remember {
                        mutableStateOf(surveyEnvironment(this@MainActivity))
                    }
                    // The task name selects the plan and the resource ceiling (Aura §4.4).
                    // Blank is an unscoped session — the pre-existing behaviour — so the
                    // field adds the ability to scope without changing the default.
                    var taskProfile by remember { mutableStateOf("") }
                    var relayError by remember {
                        mutableStateOf(EnvelopeSink.lastRelayError(this@MainActivity))
                    }

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Text(stringResource(R.string.app_title), style = MaterialTheme.typography.headlineSmall)
                        var localeMode by remember {
                            mutableStateOf(LocaleController.mode(this@MainActivity))
                        }
                        Button(
                            onClick = {
                                val index = LocaleController.modes.indexOf(localeMode)
                                localeMode = LocaleController.modes[(index + 1) % LocaleController.modes.size]
                                LocaleController.setMode(this@MainActivity, localeMode)
                                recreate()
                            },
                        ) {
                            Text(
                                stringResource(
                                    when (localeMode) {
                                        LocaleController.ENGLISH -> R.string.language_en
                                        LocaleController.SIMPLIFIED_CHINESE -> R.string.language_zh_hans
                                        LocaleController.TRADITIONAL_CHINESE -> R.string.language_zh_hant
                                        else -> R.string.language_system
                                    },
                                ),
                            )
                        }
                        // P0-3 / P1-6:「已启动 / 已连接」由状态机推出来,不是几个布尔各拼一句。
                        val relayOnNow = RelayClient.isEnabled(this@MainActivity)
                        val derived = ProtectionState.derive(
                            sessionActive = sessionActive,
                            accessibilityBound = GuardAccessibilityService.isBound(),
                            relayEnabled = relayOnNow,
                            relayLastOkMs = RelayClient.lastOkMs(this@MainActivity),
                            relayLastErrorMs = EnvelopeSink.lastRelayErrorMs(this@MainActivity),
                            nowMs = System.currentTimeMillis(),
                        )
                        Text(
                            when (derived.guard) {
                                ProtectionState.Guard.STOPPED -> stringResource(R.string.guard_stopped)
                                ProtectionState.Guard.PERMISSION_REQUIRED ->
                                    stringResource(R.string.guard_permission_required)
                                ProtectionState.Guard.DEGRADED -> stringResource(
                                    R.string.guard_degraded,
                                    derived.reasons.joinToString(", ") { it.name.lowercase() },
                                )
                                ProtectionState.Guard.ACTIVE -> stringResource(R.string.guard_active)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            if (sessionActive) {
                                stringResource(R.string.session_active, sessionId)
                            } else {
                                stringResource(R.string.session_inactive)
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )

                        Text(
                            formatRisk(lastRisk),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        envelopePath?.let {
                            Text(stringResource(R.string.events_path, it), style = MaterialTheme.typography.labelSmall)
                        }

                        OutlinedTextField(
                            value = taskProfile,
                            onValueChange = { taskProfile = it },
                            label = { Text(stringResource(R.string.task_profile_label)) },
                        )

                        // Whether a confirmation can actually reach the user, and whether the
                        // engine is reachable at all. Both were previously invisible: the app
                        // looked identical with notifications denied and with the relay
                        // pointing nowhere.
                        if (!notificationsGranted) {
                            Text(
                                stringResource(R.string.notif_permission_rationale),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Text(
                            when (derived.relay) {
                                ProtectionState.Relay.DISABLED -> stringResource(R.string.relay_state_disabled)
                                ProtectionState.Relay.CONNECTING -> stringResource(R.string.relay_state_connecting)
                                ProtectionState.Relay.CONNECTED -> stringResource(
                                    R.string.relay_state_connected,
                                    java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT)
                                        .format(java.util.Date(RelayClient.lastOkMs(this@MainActivity))),
                                )
                                ProtectionState.Relay.DEGRADED -> stringResource(
                                    R.string.relay_state_degraded,
                                    relayError?.substringAfter('|') ?: "",
                                )
                            },
                            style = MaterialTheme.typography.labelSmall,
                        )

                        // Environment risk ((A)I Sees A5/A6): what else on this
                        // device can read the agent's input. Surveyed here rather
                        // than only at install time because another accessibility
                        // service or receiver can appear at any moment.
                        Text(
                            envSummary,
                            style = MaterialTheme.typography.bodySmall,
                        )

                        Button(
                            onClick = {
                                sessionId = SessionState.start(this@MainActivity)
                                GuardForegroundService.start(this@MainActivity)
                                sessionActive = true
                                // Naming the task selects the plan and the resource ceiling
                                // (Aura §4.4). Emitted through the accessibility service
                                // because that is what holds the Context the envelope needs.
                                GuardAccessibilityService.emitSessionStartIfBound(
                                    taskProfile = taskProfile.ifBlank { null },
                                    taskApps = emptyList(),
                                )
                                envSummary = surveyEnvironment(this@MainActivity)
                                lastRisk = EnvelopeSink.lastRiskJson(this@MainActivity)
                                envelopePath = EnvelopeSink.lastEnvelopePath(this@MainActivity)
                            },
                            enabled = !sessionActive,
                        ) {
                            Text(stringResource(R.string.start_session))
                        }

                        Button(
                            onClick = {
                                GuardAccessibilityService.emitSessionEndIfBound()
                                SessionState.stop(this@MainActivity)
                                GuardForegroundService.stop(this@MainActivity)
                                sessionActive = false
                            },
                            enabled = sessionActive,
                        ) {
                            Text(stringResource(R.string.stop_session))
                        }

                        Button(
                            onClick = {
                                lastRisk = EnvelopeSink.lastRiskJson(this@MainActivity)
                                envelopePath = EnvelopeSink.lastEnvelopePath(this@MainActivity)
                                envSummary = surveyEnvironment(this@MainActivity)
                                relayError = EnvelopeSink.lastRelayError(this@MainActivity)
                            },
                        ) {
                            Text(stringResource(R.string.refresh_risk))
                        }

                        // P1-6:本地事件记录的清除入口(以前只能靠 adb 删文件)。
                        var eventBytes by remember {
                            mutableStateOf(EnvelopeSink.totalBytes(this@MainActivity))
                        }
                        var clearedNote by remember { mutableStateOf<String?>(null) }
                        Button(
                            onClick = {
                                val n = EnvelopeSink.clearAll(this@MainActivity)
                                eventBytes = EnvelopeSink.totalBytes(this@MainActivity)
                                envelopePath = null
                                clearedNote = getString(R.string.events_cleared, n)
                            },
                        ) {
                            Text(stringResource(R.string.clear_events, "${eventBytes / 1024} KB"))
                        }
                        clearedNote?.let { Text(it, style = MaterialTheme.typography.labelSmall) }

                        Button(
                            onClick = {
                                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                            },
                        ) {
                            Text(stringResource(R.string.open_accessibility))
                        }

                        var relayOn by remember {
                            mutableStateOf(RelayClient.isEnabled(this@MainActivity))
                        }
                        var relayUrl by remember {
                            mutableStateOf(RelayClient.url(this@MainActivity))
                        }
                        var relayToken by remember { mutableStateOf("") }
                        Button(
                            onClick = {
                                relayOn = !relayOn
                                RelayClient.setEnabled(this@MainActivity, relayOn)
                                if (relayOn) {
                                    RelayClient.setEndpoint(this@MainActivity, relayUrl, "")
                                }
                            },
                        ) {
                            Text(stringResource(if (relayOn) R.string.relay_on else R.string.relay_off))
                        }
                        if (relayOn) {
                            OutlinedTextField(
                                value = relayUrl,
                                onValueChange = {
                                    relayUrl = it
                                    RelayClient.setEndpoint(this@MainActivity, it, "")
                                },
                                label = { Text(stringResource(R.string.desktop_api_url)) },
                                singleLine = true,
                            )
                            // P1-6:令牌不回显。输入框永远空着,保存后只说"已保存(加密)";
                            // 存进 Keystore 封装(TokenVault),不再是明文 prefs。
                            var tokenSaved by remember {
                                mutableStateOf(RelayClient.hasToken(this@MainActivity))
                            }
                            OutlinedTextField(
                                value = relayToken,
                                onValueChange = { relayToken = it },
                                label = { Text(stringResource(R.string.bearer_token)) },
                                singleLine = true,
                                visualTransformation =
                                    androidx.compose.ui.text.input.PasswordVisualTransformation(),
                            )
                            Button(
                                onClick = {
                                    RelayClient.setEndpoint(this@MainActivity, relayUrl, relayToken)
                                    relayToken = ""
                                    tokenSaved = RelayClient.hasToken(this@MainActivity)
                                },
                                enabled = relayToken.isNotBlank(),
                            ) {
                                Text(stringResource(R.string.save))
                            }
                            Text(
                                stringResource(if (tokenSaved) R.string.token_saved else R.string.token_missing),
                                style = MaterialTheme.typography.labelSmall,
                            )
                            Text(stringResource(R.string.relay_help), style = MaterialTheme.typography.labelSmall)

                            // 适配器公钥。没有这个,那把在 Keystore 里的密钥就没有
                            // 任何办法进到桌面的注册表里 —— 一个建好了却无法登记的
                            // 密钥,等于这个机制没接上。
                            var adapterKey by remember { mutableStateOf<String?>(null) }
                            Button(onClick = { adapterKey = AdapterSigner.ensureKeyAndPublicHex() }) {
                                Text(stringResource(R.string.show_adapter_key))
                            }
                            adapterKey?.let { k ->
                                Text(
                                    stringResource(R.string.adapter_key_help),
                                    style = MaterialTheme.typography.labelSmall,
                                )
                                // 可选中,好让人复制出去。整串 130 个十六进制字符
                                // 手抄是不现实的。
                                OutlinedTextField(
                                    value = k,
                                    onValueChange = {},
                                    readOnly = true,
                                    label = { Text("public_key") },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Run the (A)I Sees A5/A6 environment survey and return a one-line summary.
     *
     * On API 30+ the receiver half is limited to packages declared visible in the
     * manifest `<queries>` block, so a clean result means "nothing visible is
     * listening", not "nothing is listening" — the summary says so rather than
     * implying a guarantee.
     */
    private fun surveyEnvironment(context: Context): String = try {
        val survey = EnvironmentScanner.scan(context)
        if (survey.isClean) {
            getString(R.string.env_clean)
        } else {
            getString(R.string.env_risk, survey.summary())
        }
    } catch (e: Exception) {
        getString(R.string.env_unknown, e.message ?: "error")
    }

    private fun formatRisk(raw: String?): String {
        if (raw.isNullOrBlank()) return getString(R.string.last_risk_none)
        return try {
            val o = JSONObject(raw)
            getString(R.string.last_risk, o.optString("rule_id"), o.optString("message"))
        } catch (_: Exception) {
            getString(R.string.last_risk_raw, raw)
        }
    }
}
