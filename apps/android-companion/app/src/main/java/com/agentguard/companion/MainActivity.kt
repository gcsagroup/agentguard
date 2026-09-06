package com.agentguard.companion

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.json.JSONObject

internal fun agentGuardColorScheme(dark: Boolean) =
    if (dark) darkColorScheme() else lightColorScheme()

class MainActivity : ComponentActivity() {

    private val sessionActiveUi = mutableStateOf(false)
    private val lastRiskUi = mutableStateOf<String?>(null)
    private val relayErrorUi = mutableStateOf<String?>(null)
    private val notificationsGrantedUi = mutableStateOf(true)
    private val sessionListener: (Boolean, String) -> Unit = { active, _ ->
        runOnUiThread {
            sessionActiveUi.value = active
        }
    }

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
            notificationsGrantedUi.value = granted
        }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            notificationsGrantedUi.value = true
            return
        }
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        notificationsGrantedUi.value = granted
        if (!granted) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        // Ask before the first session, not on first risk: the permission is what makes a
        // confirmation reachable, and finding out it is missing at the moment a payment needs
        // approving is finding out too late.
        ensureNotificationPermission()
        SessionState.restore(this)
        sessionActiveUi.value = SessionState.active
        refreshPersistedState()
        setContent {
            // MaterialTheme() defaults to a light palette even when the system is dark. With
            // edge-to-edge enabled that produced white status-bar icons on a white Surface and
            // made the app claim dark-mode support without actually rendering one. Keep the
            // platform's contrast decision and the Compose surface on the same configuration.
            MaterialTheme(
                colorScheme = agentGuardColorScheme(isSystemInDarkTheme()),
            ) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    // 显式读取 .value，让 Compose 把外部生命周期状态登记为快照依赖。
                    val sessionActive = sessionActiveUi.value
                    var lastRisk by lastRiskUi
                    var envSummary by remember {
                        mutableStateOf(surveyEnvironment(this@MainActivity))
                    }
                    // The task name selects the plan and the resource ceiling (Aura §4.4).
                    // Blank is an unscoped session — the pre-existing behaviour — so the
                    // field adds the ability to scope without changing the default.
                    var taskProfile by remember { mutableStateOf("") }
                    var relayError by relayErrorUi
                    var showDeveloperSettings by remember { mutableStateOf(false) }
                    val notificationsGranted = notificationsGrantedUi.value

                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            // targetSdk 35+ 强制边到边:内容会画到状态栏 / 导航栏底下。safeDrawingPadding
                            // 把系统栏(与刘海、IME)的区域让出来;onCreate 里的 enableEdgeToEdge 让 API 35
                            // 以下也走同一套布局,而不是两种版本两种样子(真机报告 P2-2 的 Android 15/16 回归项)。
                            .safeDrawingPadding()
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
                            notificationsGranted = notificationsGranted,
                        )
                        Text(
                            when (derived.guard) {
                                ProtectionState.Guard.STOPPED -> stringResource(R.string.guard_stopped)
                                ProtectionState.Guard.PERMISSION_REQUIRED ->
                                    stringResource(R.string.guard_permission_required)
                                ProtectionState.Guard.DEGRADED -> stringResource(
                                    R.string.guard_degraded,
                                    derived.reasons.joinToString(", ") { localizedReason(it) },
                                )
                                ProtectionState.Guard.ACTIVE -> stringResource(R.string.guard_active)
                            },
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Text(
                            formatRisk(lastRisk),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        OutlinedTextField(
                            value = taskProfile,
                            onValueChange = { taskProfile = it },
                            label = { Text(stringResource(R.string.task_profile_label)) },
                            supportingText = { Text(stringResource(R.string.task_profile_help)) },
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
                        // Environment risk ((A)I Sees A5/A6): what else on this
                        // device can read the agent's input. Surveyed here rather
                        // than only at install time because another accessibility
                        // service or receiver can appear at any moment.
                        envSummary?.let {
                            Text(it, style = MaterialTheme.typography.bodySmall)
                        }

                        Button(
                            onClick = {
                                val started = SessionState.start(
                                    this@MainActivity,
                                    observerBound = GuardAccessibilityService.isBound(),
                                )
                                if (started == null) {
                                    // Start 在无权限时是授权引导，不会制造会话或前台“监控中”通知。
                                    startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                                    return@Button
                                }
                                GuardSessionNotification.show(this@MainActivity)
                                sessionActiveUi.value = SessionState.active
                                // Naming the task selects the plan and the resource ceiling
                                // (Aura §4.4). Emitted through the accessibility service
                                // because that is what holds the Context the envelope needs.
                                GuardAccessibilityService.emitSessionStartIfBound(
                                    taskProfile = taskProfile.ifBlank { null },
                                    taskApps = emptyList(),
                                )
                                envSummary = surveyEnvironment(this@MainActivity)
                                lastRisk = EnvelopeSink.lastRiskJson(this@MainActivity)
                            },
                            enabled = !sessionActive,
                        ) {
                            Text(stringResource(R.string.start_session))
                        }

                        Button(
                            onClick = {
                                GuardAccessibilityService.emitSessionEndIfBound()
                                SessionState.stop(this@MainActivity)
                                GuardSessionNotification.hide(this@MainActivity)
                                sessionActiveUi.value = SessionState.active
                            },
                            enabled = sessionActive,
                        ) {
                            Text(stringResource(R.string.stop_session))
                        }

                        Button(
                            onClick = {
                                lastRisk = EnvelopeSink.lastRiskJson(this@MainActivity)
                                envSummary = surveyEnvironment(this@MainActivity)
                                relayError = EnvelopeSink.lastRelayError(this@MainActivity)
                            },
                        ) {
                            Text(stringResource(R.string.refresh_risk))
                        }

                        // P1-6:本地事件记录的清除入口(以前只能靠 adb 删文件)。
                        var eventBytes by remember {
                            mutableLongStateOf(EnvelopeSink.totalBytes(this@MainActivity))
                        }
                        var clearedNote by remember { mutableStateOf<String?>(null) }
                        var showClearConfirmation by remember { mutableStateOf(false) }
                        Button(
                            onClick = { showClearConfirmation = true },
                            modifier = Modifier.testTag("events.clear"),
                        ) {
                            Text(stringResource(R.string.clear_events, "${eventBytes / 1024} KB"))
                        }
                        Text(
                            stringResource(R.string.local_events_note),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (showClearConfirmation) {
                            AlertDialog(
                                onDismissRequest = { showClearConfirmation = false },
                                title = { Text(stringResource(R.string.clear_events_title)) },
                                text = { Text(stringResource(R.string.clear_events_message)) },
                                confirmButton = {
                                    TextButton(
                                        onClick = {
                                            val n = EnvelopeSink.clearAll(this@MainActivity)
                                            eventBytes = EnvelopeSink.totalBytes(this@MainActivity)
                                            clearedNote = resources.getQuantityString(R.plurals.events_cleared, n, n)
                                            showClearConfirmation = false
                                        },
                                    ) {
                                        Text(stringResource(R.string.clear_events_confirm))
                                    }
                                },
                                dismissButton = {
                                    TextButton(onClick = { showClearConfirmation = false }) {
                                        Text(stringResource(R.string.cancel))
                                    }
                                },
                            )
                        }
                        clearedNote?.let { Text(it, style = MaterialTheme.typography.labelSmall) }

                        Button(
                            onClick = {
                                startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                            },
                        ) {
                            Text(stringResource(R.string.open_accessibility))
                        }

                        if (RelayClient.isAvailable()) {
                            Button(
                                onClick = { showDeveloperSettings = !showDeveloperSettings },
                                modifier = Modifier.testTag("developer.toggle"),
                            ) {
                                Text(
                                    stringResource(
                                        if (showDeveloperSettings) {
                                            R.string.hide_developer_settings
                                        } else {
                                            R.string.show_developer_settings
                                        },
                                    ),
                                )
                            }
                        }

                        if (RelayClient.isAvailable() && showDeveloperSettings) {
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
    }

    override fun onStart() {
        super.onStart()
        SessionState.addListener(sessionListener)
    }

    override fun onResume() {
        super.onResume()
        sessionActiveUi.value = SessionState.active
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationsGrantedUi.value =
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        }
        refreshPersistedState()
    }

    override fun onStop() {
        SessionState.removeListener(sessionListener)
        super.onStop()
    }

    /** 风险可能在本 Activity 退到后台后由无障碍服务写入；恢复前台时必须立即反映。 */
    private fun refreshPersistedState() {
        lastRiskUi.value = EnvelopeSink.lastRiskJson(this)
        relayErrorUi.value = EnvelopeSink.lastRelayError(this)
    }

    internal fun localizedReason(reason: ProtectionState.Reason): String = getString(
        when (reason) {
            ProtectionState.Reason.NO_SESSION -> R.string.reason_no_session
            ProtectionState.Reason.ACCESSIBILITY_NOT_BOUND -> R.string.reason_accessibility_not_bound
            ProtectionState.Reason.RELAY_ERROR -> R.string.reason_relay_error
            ProtectionState.Reason.RELAY_NEVER_CONNECTED -> R.string.reason_relay_never_connected
            ProtectionState.Reason.RELAY_STALE -> R.string.reason_relay_stale
            ProtectionState.Reason.NOTIFICATIONS_DENIED -> R.string.reason_notifications_denied
        },
    )

    /**
     * Run the (A)I Sees A5/A6 environment survey and return a one-line summary.
     *
     * On API 30+ the receiver half is limited to packages declared visible in the
     * manifest `<queries>` block. A clean result therefore stays off the consumer
     * surface instead of being presented as a guarantee. Risks and incomplete scans
     * are shown without package names, internal counters, or exception text.
     */
    private fun surveyEnvironment(context: Context): String? = try {
        val survey = EnvironmentScanner.scan(context)
        val hasVisibleRisk = survey.broadcastInputReceivers.isNotEmpty() ||
            survey.foreignA11yServices.isNotEmpty() || survey.logIsReadable
        when {
            hasVisibleRisk -> getString(R.string.env_risk)
            !survey.isComplete -> getString(R.string.env_unknown)
            else -> null
        }
    } catch (_: Exception) {
        getString(R.string.env_unknown)
    }

    private fun formatRisk(raw: String?): String {
        if (raw.isNullOrBlank()) return getString(R.string.last_risk_none)
        return try {
            val o = JSONObject(raw)
            val message = o.optString("message").takeIf { it.isNotBlank() }
                ?: return getString(R.string.last_risk_unavailable)
            getString(R.string.last_risk, message)
        } catch (_: Exception) {
            getString(R.string.last_risk_unavailable)
        }
    }
}
