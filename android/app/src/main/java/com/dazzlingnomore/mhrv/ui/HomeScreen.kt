package com.dazzlingnomore.mhrv.ui

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.HourglassBottom
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.dazzlingnomore.mhrv.BuildConfig
import com.dazzlingnomore.mhrv.CaInstall
import com.dazzlingnomore.mhrv.ConfigStore
import com.dazzlingnomore.mhrv.ConnectionMode
import com.dazzlingnomore.mhrv.CuratedGroups
import com.dazzlingnomore.mhrv.DEFAULT_SNI_POOL
import com.dazzlingnomore.mhrv.DeploymentEntry
import com.dazzlingnomore.mhrv.FrontingGroup
import com.dazzlingnomore.mhrv.Mode
import com.dazzlingnomore.mhrv.Native
import com.dazzlingnomore.mhrv.NetworkDetect
import com.dazzlingnomore.mhrv.ProfileStore
import com.dazzlingnomore.mhrv.R
import com.dazzlingnomore.mhrv.RahgozarConfig
import com.dazzlingnomore.mhrv.SplitMode
import com.dazzlingnomore.mhrv.UiLang
import com.dazzlingnomore.mhrv.UpdateInstaller
import com.dazzlingnomore.mhrv.VpnStateSync
import com.dazzlingnomore.mhrv.ui.theme.ErrRed
import com.dazzlingnomore.mhrv.ui.theme.OkGreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject

/**
 * UI state returned by the Activity after the CA install flow finishes,
 * so the screen can show a matching snackbar. Kept as a sum type — a raw
 * string message would conflate "installed" vs. "failed to export".
 */
sealed class CaInstallOutcome {
    object Installed : CaInstallOutcome()

    /**
     * Cert not found in the AndroidCAStore after the Settings activity
     * returned. Carries an optional downloadPath so the snackbar can tell
     * the user where the file landed (Downloads or app-private external).
     */
    data class NotInstalled(
        val downloadPath: String?,
    ) : CaInstallOutcome()

    data class Failed(
        val message: String,
    ) : CaInstallOutcome()
}

/**
 * Top-level screen. Intentionally one scrollable page rather than tabs —
 * first-run users need to see everything (deployment IDs, cert button,
 * Connect) on one surface. The Connect/Disconnect button sits right under
 * the Mode dropdown so a long deployment-ID list can't push it off-screen
 * for daily-use taps. Anything that isn't first-run critical (Apps Script
 * setup once filled, SNI pool, Advanced, Logs) lives in collapsible
 * sections so the default view stays short.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    onStart: () -> Unit,
    onStop: () -> Unit,
    onInstallCaConfirmed: () -> Unit,
    caOutcome: CaInstallOutcome?,
    onCaOutcomeConsumed: () -> Unit,
    onLangChange: (UiLang) -> Unit = {},
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    // Persisted form state. Any edit writes back to disk immediately —
    // cheap at this write rate, avoids "I tapped Start before saving" bugs.
    var cfg by remember { mutableStateOf(ConfigStore.load(ctx)) }

    fun persist(new: RahgozarConfig) {
        // Optimistically reflect the user's edit so the form doesn't
        // snap back mid-typing if the save fails. On a successful
        // write we re-read from disk so the in-memory state matches
        // the persisted bytes exactly — picking up the refresh-token
        // snapshot that ConfigStore.save preserves internally via
        // its own prepareForSave pass. Calling prepareForSave here
        // would read config.json a second time; if another writer
        // landed between the two reads, the UI state could diverge
        // from what actually hit disk.
        cfg = new
        val saved = ConfigStore.save(ctx, new)
        if (!saved) {
            // Surface the failure; the next snackbar slot will show
            // it. The in-memory cfg reflects the user's edit, but
            // config.json on disk does not.
            scope.launch {
                snackbar.showSnackbar(
                    ctx.getString(R.string.snack_config_save_failed),
                    withDismissAction = true,
                )
            }
            return
        }
        cfg = ConfigStore.load(ctx)
        // Only after a successful write do we touch the profile
        // pointer. A failed save would have left config.json with
        // the OLD bytes (which may still match the active profile),
        // so clearing active in that case would be a false claim.
        ProfileStore.clearActiveIfAny(ctx)
    }

    // CA install dialog visibility.
    var showInstallDialog by rememberSaveable { mutableStateOf(false) }

    // One-shot auto update check on first composition. Silent if we're
    // already on the latest (no point nagging about a network miss or an
    // up-to-date install); surfaces a snackbar AND sets the pending-update
    // state that drives the badge on the version button — the badge stays
    // visible after the snackbar auto-dismisses so the user can act on
    // the update later. rememberSaveable so it doesn't re-fire on every
    // config change / rotation; the badge state itself lives in the
    // UpdateInstaller singleton so it survives the activity recreation
    // that rememberSaveable's gate would otherwise skip refreshing.
    var autoUpdateChecked by rememberSaveable { mutableStateOf(false) }
    LaunchedEffect(autoUpdateChecked) {
        if (autoUpdateChecked) return@LaunchedEffect
        autoUpdateChecked = true
        val json =
            withContext(Dispatchers.IO) {
                runCatching { Native.checkUpdate() }.getOrNull()
            }
        val state = UpdateInstaller.parseCheckResult(json)
        if (state is UpdateInstaller.State.Available) {
            UpdateInstaller.markPendingUpdate(state)
            offerInstall(ctx, scope, snackbar, state)
        }
    }

    val pendingUpdate by UpdateInstaller.pendingUpdate.collectAsState()
    val offerInFlight by UpdateInstaller.offerInFlight.collectAsState()

    // Gate Start/Stop on the service's actual state transition rather
    // than a fixed timer. The previous 2s cooldown was shorter than the
    // worst-case teardown (Tun2proxy.stop + 4s join + 5s rt.shutdown_timeout
    // ≈ 9s on the slowest path), which let the user fire a fresh Connect
    // while the previous Stop's native cleanup was still releasing the
    // listener port — the new startProxy then failed with "Address already
    // in use".
    //
    // `awaitingRunning` holds the value we expect VpnStateSync.isRunning to
    // settle on after the user's action; null means "no transition in
    // flight". The LaunchedEffect below suspends on the StateFlow until
    // the predicate matches, with a 12s backstop in case the service
    // failed before flipping the flag (e.g., establish() returned null).
    // Side benefit: this also debounces the rapid-tap EGL renderer crash
    // the old timer was guarding against.
    var awaitingRunning by remember { mutableStateOf<Boolean?>(null) }
    val transitioning = awaitingRunning != null
    LaunchedEffect(awaitingRunning) {
        val target = awaitingRunning ?: return@LaunchedEffect
        try {
            withTimeoutOrNull(12_000) {
                VpnStateSync.isRunning.first { it == target }
            }
        } finally {
            awaitingRunning = null
        }
    }

    // Surface CA install result as a snackbar. We consume the outcome
    // after showing so a recomposition doesn't re-trigger it.
    LaunchedEffect(caOutcome) {
        val o = caOutcome ?: return@LaunchedEffect
        val msg =
            when (o) {
                is CaInstallOutcome.Installed -> {
                    ctx.getString(R.string.snack_ca_installed)
                }

                is CaInstallOutcome.NotInstalled -> {
                    if (!o.downloadPath.isNullOrBlank()) {
                        ctx.getString(R.string.snack_ca_not_installed_with_path, o.downloadPath)
                    } else {
                        ctx.getString(R.string.snack_ca_not_installed_retry)
                    }
                }

                is CaInstallOutcome.Failed -> {
                    o.message
                }
            }
        snackbar.showSnackbar(msg, withDismissAction = true)
        onCaOutcomeConsumed()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                actions = {
                    // Language toggle — cycles AUTO → FA → EN → AUTO.
                    // Saving writes to config.json and triggers activity
                    // recreate, which re-applies the AppCompatDelegate
                    // locale (and flips LTR ↔ RTL accordingly). Kept as
                    // a small label button instead of an icon because
                    // "AUTO/FA/EN" communicates the current state at a
                    // glance; a flag icon alone would be ambiguous.
                    TextButton(
                        onClick = {
                            val next =
                                when (cfg.uiLang) {
                                    UiLang.AUTO -> UiLang.FA
                                    UiLang.FA -> UiLang.EN
                                    UiLang.EN -> UiLang.AUTO
                                }
                            persist(cfg.copy(uiLang = next))
                            onLangChange(next)
                        },
                    ) {
                        Text(
                            text =
                                when (cfg.uiLang) {
                                    UiLang.AUTO -> "AUTO"
                                    UiLang.FA -> "FA"
                                    UiLang.EN -> "EN"
                                },
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }

                    // Tap the version label to check for updates. When the
                    // auto-check has already found a newer release, the
                    // BadgedBox draws a red dot on the corner and tapping
                    // skips the re-check and jumps straight to the install
                    // snackbar.
                    var checking by remember { mutableStateOf(false) }
                    BadgedBox(
                        badge = {
                            if (pendingUpdate != null) {
                                Badge(containerColor = ErrRed)
                            }
                        },
                        modifier = Modifier.padding(end = 4.dp),
                    ) {
                        TextButton(
                            enabled = !checking && !offerInFlight,
                            onClick = {
                                // Cheap UI guard — `offerInstall` also calls
                                // `tryAcquireOffer` so two taps that race past
                                // the recompose window still can't both win.
                                if (checking || offerInFlight) return@TextButton
                                // Always re-check on tap, even when `pendingUpdate`
                                // is already set: the cached state can go stale
                                // (asset URL expires, release replaced, a newer
                                // release lands, a previously-unsupported ABI
                                // gains an asset). The badge stays driven by the
                                // most recent successful check; the next call
                                // here either confirms it, refreshes it, or
                                // clears it (when the latest is now UpToDate).
                                checking = true
                                scope.launch {
                                    try {
                                        val json =
                                            withContext(Dispatchers.IO) {
                                                runCatching { Native.checkUpdate() }.getOrNull()
                                            }
                                        val state = UpdateInstaller.parseCheckResult(json)
                                        when (state) {
                                            is UpdateInstaller.State.Available -> {
                                                UpdateInstaller.markPendingUpdate(state)
                                                offerInstall(ctx, scope, snackbar, state)
                                            }

                                            is UpdateInstaller.State.UpToDate -> {
                                                // Clear the badge: the cached
                                                // "available" state is no longer
                                                // accurate. Surface the result so
                                                // the user knows the tap did
                                                // something.
                                                UpdateInstaller.clearPendingUpdate()
                                                snackbar.showSnackbar(
                                                    summarizeUpdateCheck(json),
                                                    withDismissAction = true,
                                                )
                                            }

                                            else -> {
                                                // Error / offline: leave the
                                                // existing badge alone (a prior
                                                // successful check may still be
                                                // valid) and just surface the
                                                // failure for this attempt.
                                                snackbar.showSnackbar(
                                                    summarizeUpdateCheck(json),
                                                    withDismissAction = true,
                                                )
                                            }
                                        }
                                    } finally {
                                        checking = false
                                    }
                                }
                            },
                        ) {
                            Text(
                                text =
                                    if (checking) {
                                        stringResource(R.string.tb_check_update_checking)
                                    } else {
                                        stringResource(R.string.tb_version_prefix) +
                                            runCatching { Native.version() }.getOrDefault("?")
                                    },
                                style = MaterialTheme.typography.labelMedium,
                            )
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { inner ->
        Column(
            modifier =
                Modifier
                    .padding(inner)
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // Config import/export bar — paste from clipboard + export + QR.
            ConfigSharingBar(
                cfg = cfg,
                onImport = { persist(it) },
                onSnackbar = { snackbar.showSnackbar(it) },
            )

            // Multi-profile bar — switch between saved configs without
            // re-typing deployment IDs / auth keys (e.g. one Apps Script
            // profile, one Full tunnel profile). Writes through to the
            // same `config.json` the Rust runtime reads. When a profile
            // carries a different `ui_lang`, we route through the same
            // onLangChange path as the top-bar toggle so the activity
            // recreates with the right locale + RTL/LTR direction.
            ProfileBar(
                cfg = cfg,
                onConfigChange = { cfg = it },
                onLangChange = onLangChange,
                onSnackbar = { snackbar.showSnackbar(it) },
            )

            SectionHeader(stringResource(R.string.sec_mode))
            ModeDropdown(
                mode = cfg.mode,
                onChange = { persist(cfg.copy(mode = it)) },
            )

            // Connect/Disconnect lives right under Mode so users with a long
            // deployment-ID list don't have to scroll past it on every
            // session. Disabled state still acts as the "you're not set up
            // yet" signal — they'll expand the Apps Script section below to
            // resolve it.
            val isVpnRunning by VpnStateSync.isRunning.collectAsState()
            Button(
                onClick = {
                    if (isVpnRunning) {
                        awaitingRunning = false
                        onStop()
                    } else {
                        awaitingRunning = true
                        // Connect flow: auto-resolve google_ip so we don't
                        // hand the proxy a stale anycast target; repair
                        // front_domain if it got corrupted into an IP
                        // (SNI has to be a hostname); then fire onStart.
                        // All three steps go through the Compose persist()
                        // so a subsequent field edit can't overwrite the
                        // fresh values with pre-resolve ones.
                        scope.launch {
                            // LocalBypass has no relay path, so google_ip
                            // / front_domain repair is dead weight — and
                            // worse, the blocking resolveGoogleIp() call
                            // adds startup latency for a knob this mode
                            // doesn't read. Skip the repair entirely.
                            var updated = cfg
                            if (cfg.mode != Mode.LOCAL_BYPASS) {
                                // Only auto-fill google_ip if it's empty.
                                // Issue #71: some Iranian ISPs return
                                // poisoned A records for www.google.com
                                // that resolve but then refuse TLS (or
                                // route to a Google IP that's not on the
                                // GFE and can't handle our SNI-rewrite).
                                // If the user has manually set a working
                                // IP (e.g. 216.239.38.120), we must NOT
                                // overwrite it with a poisoned fresh
                                // lookup just because the two values
                                // differ. They can still force a
                                // re-resolve via the explicit
                                // "Auto-detect" button above.
                                if (updated.googleIp.isBlank()) {
                                    val fresh =
                                        withContext(Dispatchers.IO) {
                                            NetworkDetect.resolveGoogleIp()
                                        }
                                    if (!fresh.isNullOrBlank()) {
                                        updated = updated.copy(googleIp = fresh)
                                    }
                                }
                                if (updated.frontDomain.isBlank() ||
                                    updated.frontDomain.parseAsIpOrNull() != null
                                ) {
                                    updated = updated.copy(frontDomain = "www.google.com")
                                }
                            }
                            if (updated !== cfg) persist(updated)
                            onStart()
                        }
                    }
                },
                enabled =
                    (
                        // Connect is enabled when the proxy is already
                        // running OR the selected mode has its required
                        // credentials/config. The predicate lives on
                        // RahgozarConfig so UI and service preflight stay
                        // in lock-step when new modes land.
                        isVpnRunning || cfg.canStartCurrentMode
                    ) && !transitioning,
                colors =
                    ButtonDefaults.buttonColors(
                        containerColor = if (isVpnRunning) ErrRed else OkGreen,
                        contentColor = androidx.compose.ui.graphics.Color.White,
                        disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
                    ),
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 52.dp),
            ) {
                Text(
                    when {
                        transitioning -> "…"
                        isVpnRunning -> stringResource(R.string.btn_disconnect)
                        else -> stringResource(R.string.btn_connect)
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }

            // Upstream-proxy hint: while running in Direct mode, surface the
            // local listen port with a one-tap copy so users wiring this up
            // as an upstream don't have to dig through config. Direct is the
            // only mode that makes sense here — apps_script and full try to
            // relay everything via Apps Script, which breaks binary protocols
            // like Psiphon's. See docs/use-as-upstream.md.
            //
            // Gating on PROXY_ONLY: Android allows only one active VPN at a
            // time. If rahgozar is running its own VpnService (VPN_TUN mode),
            // Psiphon cannot establish its own VPN and the upstream address
            // here is not actionable. Show the warning copy first so the
            // user knows to stop, flip to PROXY_ONLY, and Connect again
            // before pasting the address into Psiphon.
            //
            // Vertical Column instead of horizontal Row: in Persian and at
            // larger font sizes the label + monospace address + copy button
            // would cramp into a single line. Stacking lets each part wrap
            // naturally and keeps the copy button reachable.
            if (isVpnRunning && cfg.mode == Mode.DIRECT) {
                Spacer(Modifier.height(8.dp))
                val clipboard = LocalClipboardManager.current
                val ctx = LocalContext.current
                val upstreamPort = cfg.listenPort
                val upstream = "127.0.0.1:$upstreamPort"
                val copiedMsg = stringResource(R.string.snack_upstream_copied, upstream)
                val proxyOnly = cfg.connectionMode == ConnectionMode.PROXY_ONLY
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    if (!proxyOnly) {
                        Text(
                            stringResource(R.string.direct_upstream_vpn_tun_warning),
                            style = MaterialTheme.typography.labelSmall,
                            color = ErrRed,
                        )
                    }
                    Text(
                        stringResource(R.string.direct_upstream_label),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        SelectionContainer(modifier = Modifier.weight(1f)) {
                            Text(
                                upstream,
                                style =
                                    MaterialTheme.typography.bodyMedium.copy(
                                        fontFamily = FontFamily.Monospace,
                                    ),
                                color = if (proxyOnly) OkGreen else MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        TextButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(upstream))
                                Toast.makeText(ctx, copiedMsg, Toast.LENGTH_SHORT).show()
                            },
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                        ) {
                            Text(
                                stringResource(R.string.btn_copy_lower),
                                style = MaterialTheme.typography.labelMedium,
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(4.dp))

            // Wrapped in a collapsible so a long ID list (10+ deployments
            // is normal in full-tunnel rotations) doesn't dominate the
            // screen once it's set up. Starts expanded for first-run users
            // (no IDs/key yet) so the form is immediately discoverable.
            //
            // Mode-gated: only modes that actually consult script_ids +
            // auth_key see this section. Switching to direct / local_bypass
            // / drive hides it entirely (the field values stay on disk so
            // they're preserved on a mode round-trip).
            if (cfg.mode.usesAppsScriptRelay()) {
                CollapsibleSection(
                    title = stringResource(R.string.sec_apps_script_relay),
                    initiallyExpanded = !cfg.hasDeploymentId || cfg.authKey.isBlank(),
                ) {
                    DeploymentIdsField(
                        urls = cfg.appsScriptUrls,
                        onChange = { persist(cfg.copy(appsScriptUrls = it)) },
                    )

                    OutlinedTextField(
                        value = cfg.authKey,
                        onValueChange = { persist(cfg.copy(authKey = it)) },
                        label = { Text(stringResource(R.string.field_auth_key)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
                        modifier = Modifier.fillMaxWidth(),
                        supportingText = {
                            Text(stringResource(R.string.help_auth_key))
                        },
                    )
                }
            }

            // Drive-mode setup. Visible only when the user has picked
            // Drive in the mode dropdown. The OAuth flow lives entirely
            // inside the JNI bridge; the section just dispatches +
            // displays status. See `Native.driveOauth*` for the
            // ~6-call surface.
            if (cfg.mode == Mode.DRIVE) {
                Spacer(Modifier.height(4.dp))
                DriveSetupSection(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            Spacer(Modifier.height(4.dp))
            SectionHeader(stringResource(R.string.sec_network))

            ConnectionModeDropdown(
                mode = cfg.connectionMode,
                onChange = { persist(cfg.copy(connectionMode = it)) },
                httpPort = cfg.listenPort,
                socks5Port = cfg.socks5Port ?: (cfg.listenPort + 1),
            )

            // google_ip / front_domain feed the SNI-rewrite tunnel and
            // the Google direct path. LOCAL_BYPASS doesn't touch either
            // (every TLS host is dialed directly with the browser's
            // real ClientHello), so the row is just clutter that
            // implies the values matter. DRIVE still resolves Google
            // endpoints via google_ip, so the fields stay visible there;
            // only Auto-detect / SNI pool / fronting groups go away in
            // DRIVE (Drive's relay never dispatches through
            // `fronting_groups` or the SNI rotation pool).
            val showsGoogleFrontingFields = cfg.mode != Mode.LOCAL_BYPASS
            val showsFrontingTechniques =
                cfg.mode != Mode.LOCAL_BYPASS && cfg.mode != Mode.DRIVE
            if (showsGoogleFrontingFields) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(
                        value = cfg.googleIp,
                        onValueChange = { persist(cfg.copy(googleIp = it)) },
                        label = { Text(stringResource(R.string.field_google_ip)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.weight(1f),
                    )
                    OutlinedTextField(
                        value = cfg.frontDomain,
                        onValueChange = { persist(cfg.copy(frontDomain = it)) },
                        label = { Text(stringResource(R.string.field_front_domain)) },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            // "Auto-detect" forces a fresh DNS resolution now. Start also
            // auto-resolves transparently, but exposing a button makes the
            // "I'm getting connect timeouts, is my google_ip stale?" case
            // a one-tap fix without needing to look up nslookup output.
            // Hidden in LOCAL_BYPASS (no google_ip dependency).
            if (showsGoogleFrontingFields) {
                TextButton(
                    onClick = {
                        scope.launch {
                            val fresh =
                                withContext(Dispatchers.IO) {
                                    NetworkDetect.resolveGoogleIp()
                                }
                            if (!fresh.isNullOrBlank()) {
                                var updated = cfg
                                if (fresh != updated.googleIp) {
                                    updated = updated.copy(googleIp = fresh)
                                }
                                // Same repair logic as the Start button —
                                // if front_domain has been corrupted into an
                                // IP we can't use it for SNI, so put the
                                // default hostname back.
                                if (updated.frontDomain.isBlank() ||
                                    updated.frontDomain.parseAsIpOrNull() != null
                                ) {
                                    updated = updated.copy(frontDomain = "www.google.com")
                                }
                                // Captured up-front so the lambda has access
                                // to the format-string resources via context
                                // before running on the IO dispatcher.
                                if (updated !== cfg) {
                                    persist(updated)
                                    snackbar.showSnackbar(
                                        ctx.getString(R.string.snack_google_ip_updated, fresh),
                                    )
                                } else {
                                    snackbar.showSnackbar(
                                        ctx.getString(R.string.snack_google_ip_current, fresh),
                                    )
                                }
                            } else {
                                snackbar.showSnackbar(ctx.getString(R.string.snack_dns_lookup_failed))
                            }
                        }
                    },
                    modifier = Modifier.align(Alignment.End),
                ) { Text(stringResource(R.string.btn_auto_detect_google_ip)) }
            }

            // App splitting — only makes sense in VPN_TUN mode.
            // PROXY_ONLY has no system-level routing to partition.
            if (cfg.connectionMode == ConnectionMode.VPN_TUN) {
                CollapsibleSection(title = stringResource(R.string.sec_app_splitting)) {
                    AppSplittingEditor(cfg = cfg, onChange = ::persist)
                }
            }

            // SNI pool + CDN fronting groups are inert in LOCAL_BYPASS
            // (no SNI rewrite, no CDN-edge dial — just direct fragmented
            // connect to every real destination) and in DRIVE (every
            // request rides the Drive-mailbox transport, which has its
            // own endpoint resolution and no fronting hop), so the
            // editors are hidden in those modes to avoid implying the
            // values matter.
            if (showsFrontingTechniques) {
                // SNI pool: collapsed by default. Users without a reason
                // to touch it should leave Rust's auto-expansion to
                // handle it.
                CollapsibleSection(title = stringResource(R.string.sec_sni_pool_tester)) {
                    SniPoolEditor(
                        cfg = cfg,
                        onChange = ::persist,
                    )
                }

                // CDN fronting groups: collapsed by default. Surfaces
                // the "discover front by hostname" flow that lets users
                // add new CDN edges without hand-editing config.json.
                // See docs/use-as-upstream.md for the underlying
                // technique.
                CollapsibleSection(title = stringResource(R.string.sec_fronting_groups)) {
                    FrontingGroupsEditor(
                        cfg = cfg,
                        onChange = ::persist,
                    )
                }
            }

            // Advanced settings: collapsed by default.
            CollapsibleSection(title = stringResource(R.string.sec_advanced)) {
                AdvancedSettings(
                    cfg = cfg,
                    onChange = ::persist,
                )
            }

            Spacer(Modifier.height(8.dp))
            // Secondary action — FilledTonalButton signals "helper" against
            // the primary Connect/Disconnect button at the top. Kept down
            // here because cert install is a one-time setup step; daily
            // users never tap it again.
            //
            // Hidden in no-MITM modes so users are never asked to add a
            // root CA for transports that keep TLS end-to-end.
            val showsCertInstall = cfg.mode.usesMitmCa()
            if (showsCertInstall) {
                FilledTonalButton(
                    onClick = { showInstallDialog = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.btn_install_mitm))
                }
            }

            // "Usage today (estimated)" — visible only while a proxy is
            // actually running (the handle is non-zero). Polls the native
            // stats counter once a second; cheap (just reads atomics on
            // the Rust side) and gives users a live feel for how close
            // they are to the Apps Script daily quota. Also links out to
            // Google's dashboard for the authoritative number — the
            // client-side estimate only sees what this device relayed,
            // not what other devices on the same deployment consumed.
            UsageTodayCard()
            // Pipeline-debug card is a development affordance — it polls
            // a native JSON snapshot once a second and renders internal
            // mux counters. Release users would just see a confusing
            // panel of integers next to no benefit, so strip it from
            // release builds the same way the system-overlay variant
            // is stripped (see RahgozarVpnService.showDebugOverlay).
            if (BuildConfig.DEBUG) {
                PipelineDebugCard()
            }

            CollapsibleSection(title = stringResource(R.string.sec_live_logs), initiallyExpanded = false) {
                LiveLogPane()
            }

            Spacer(Modifier.height(16.dp))
            // Wrapped in a collapsible so the big prose block doesn't
            // dominate the form after the user has learned the flow.
            // Starts expanded once for a fresh install so the first-run
            // instructions are immediately visible.
            // The how-to walks through the Apps Script deploy + cert
            // install flow. Auto-expand the first time a relay-mode
            // user is missing those credentials, but stay collapsed
            // for LOCAL_BYPASS (no relay, no cert) so we don't shove
            // an irrelevant wall of text in their face on first run.
            CollapsibleSection(
                title = stringResource(R.string.sec_how_to_use),
                initiallyExpanded =
                    cfg.mode.usesAppsScriptRelay() &&
                        (!cfg.hasDeploymentId || cfg.authKey.isBlank()),
            ) {
                HowToUseBody(cfg.listenPort)
            }
        }
    }

    // ---- CA install confirmation dialog ---------------------------------
    if (showInstallDialog) {
        // Export eagerly so we can show the fingerprint in the dialog body
        // — builds user confidence ("yes, that's the cert I'm trusting")
        // and gives us a usable failure path if the CA doesn't exist yet.
        val exported = remember { CaInstall.export(ctx) }
        val fp = remember(exported) { if (exported) CaInstall.fingerprint(ctx) else null }
        val cn = remember(exported) { if (exported) CaInstall.subjectCn(ctx) else null }

        AlertDialog(
            onDismissRequest = { showInstallDialog = false },
            title = { Text(stringResource(R.string.dialog_install_mitm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.dialog_install_mitm_body_1))
                    Text(stringResource(R.string.dialog_install_mitm_body_2))
                    if (fp != null) {
                        Text(
                            stringResource(
                                R.string.dialog_install_mitm_subject_fmt,
                                cn ?: stringResource(R.string.dialog_install_mitm_subject_unknown),
                            ),
                            style = MaterialTheme.typography.labelMedium,
                        )
                        Text(
                            text = "SHA-256: ${CaInstall.fingerprintHex(fp)}",
                            style = MaterialTheme.typography.labelSmall,
                            fontFamily = FontFamily.Monospace,
                        )
                    } else {
                        Text(
                            stringResource(R.string.dialog_install_mitm_cert_unavailable),
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showInstallDialog = false
                        if (fp != null) onInstallCaConfirmed()
                    },
                    enabled = fp != null,
                ) { Text(stringResource(R.string.btn_install)) }
            },
            dismissButton = {
                TextButton(onClick = { showInstallDialog = false }) {
                    Text(stringResource(R.string.btn_cancel))
                }
            },
        )
    }
}

// =========================================================================
// App splitting — ALL / ONLY / EXCEPT, plus a picker for the package list.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppSplittingEditor(
    cfg: RahgozarConfig,
    onChange: (RahgozarConfig) -> Unit,
) {
    val ctx = LocalContext.current
    var pickerOpen by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            stringResource(R.string.help_app_splitting),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Radio-style mode selector. Using Column-of-Row-with-RadioButton
        // instead of a dropdown because all three options deserve to be
        // visible simultaneously — the labels explain the contract.
        SplitModeRow(
            label = stringResource(R.string.split_all),
            selected = cfg.splitMode == SplitMode.ALL,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.ALL)) },
        )
        SplitModeRow(
            label = stringResource(R.string.split_only),
            selected = cfg.splitMode == SplitMode.ONLY,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.ONLY)) },
        )
        SplitModeRow(
            label = stringResource(R.string.split_except),
            selected = cfg.splitMode == SplitMode.EXCEPT,
            onClick = { onChange(cfg.copy(splitMode = SplitMode.EXCEPT)) },
        )

        if (cfg.splitMode != SplitMode.ALL) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    stringResource(R.string.sni_selected_count, cfg.splitApps.size),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { pickerOpen = true }) {
                    Text(stringResource(R.string.split_pick_apps))
                }
            }
        }
    }

    if (pickerOpen) {
        AppPickerDialog(
            initial = cfg.splitApps.toSet(),
            ownPackage = ctx.packageName,
            onSave = { picked ->
                onChange(cfg.copy(splitApps = picked))
                pickerOpen = false
            },
            onDismiss = { pickerOpen = false },
        )
    }
}

@Composable
private fun SplitModeRow(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth(),
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f),
        )
    }
}

// =========================================================================
// Connection mode — VPN (TUN) vs Proxy-only.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ConnectionModeDropdown(
    mode: ConnectionMode,
    onChange: (ConnectionMode) -> Unit,
    httpPort: Int,
    socks5Port: Int,
) {
    val labelVpn = stringResource(R.string.mode_vpn_tun)
    val labelProxy = stringResource(R.string.mode_proxy_only)
    val currentLabel =
        when (mode) {
            ConnectionMode.VPN_TUN -> labelVpn
            ConnectionMode.PROXY_ONLY -> labelProxy
        }
    var expanded by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = currentLabel,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.field_connection_mode)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                DropdownMenuItem(
                    text = { Text(labelVpn) },
                    onClick = {
                        onChange(ConnectionMode.VPN_TUN)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelProxy) },
                    onClick = {
                        onChange(ConnectionMode.PROXY_ONLY)
                        expanded = false
                    },
                )
            }
        }

        // Helper text under the dropdown explains what the user is
        // signing up for in each mode — especially important for
        // PROXY_ONLY, where "tap Connect" alone doesn't route anything
        // until they set the Wi-Fi proxy themselves.
        val help =
            when (mode) {
                ConnectionMode.VPN_TUN -> {
                    stringResource(R.string.help_mode_vpn_tun)
                }

                ConnectionMode.PROXY_ONLY -> {
                    stringResource(R.string.help_mode_proxy_only, httpPort, socks5Port)
                }
            }
        Text(
            help,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// =========================================================================
// Deployment IDs editor — one row per ID, with add/remove buttons. The
// "+ Add" field accepts a single ID OR a bulk paste of many separated by
// whitespace / newline / comma / semicolon — useful when migrating from
// the desktop config or pasting a freshly-deployed batch (issue: bulk add).
// =========================================================================

/** Split a bulk-pasted blob into individual entries. */
private val ID_SEPARATORS = Regex("[\\s,;]+")

@Composable
private fun DeploymentIdsField(
    urls: List<DeploymentEntry>,
    onChange: (List<DeploymentEntry>) -> Unit,
) {
    var newEntry by remember { mutableStateOf("") }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            stringResource(R.string.field_deployment_urls),
            style = MaterialTheme.typography.labelLarge,
        )

        // Existing entries — each with its own checkbox (park without
        // deleting), URL input, and remove button. A bulk paste into an
        // existing row still expands into multiple entries; the pasted
        // rows inherit the current row's enabled flag so a user toggling
        // a row off and pasting into it doesn't silently mass-enable.
        urls.forEachIndexed { index, entry ->
            // Capture the per-row description outside the semantics
            // modifier — `stringResource` is `@Composable` and can't be
            // called from the modifier lambda (which runs in the
            // layout/semantics phase, not composition).
            val checkboxCd =
                stringResource(R.string.cd_deployment_enable, index + 1)
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Checkbox(
                    checked = entry.enabled,
                    onCheckedChange = { checked ->
                        val updated = urls.toMutableList()
                        updated[index] = entry.copy(enabled = checked)
                        onChange(updated)
                    },
                    modifier = Modifier.semantics { contentDescription = checkboxCd },
                )
                OutlinedTextField(
                    value = entry.url,
                    onValueChange = { edited ->
                        val parts = edited.split(ID_SEPARATORS).filter { it.isNotBlank() }
                        val updated = urls.toMutableList()
                        if (parts.size > 1) {
                            // Bulk paste into this row: expand in place,
                            // inheriting the current row's enabled flag.
                            updated.removeAt(index)
                            updated.addAll(
                                index,
                                parts.map { DeploymentEntry(it, entry.enabled) },
                            )
                        } else {
                            // Normal typing — preserve raw input so the
                            // caret/whitespace doesn't get reformatted on
                            // every keystroke.
                            updated[index] = entry.copy(url = edited)
                        }
                        onChange(updated)
                    },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    textStyle =
                        if (entry.enabled) {
                            MaterialTheme.typography.bodySmall
                        } else {
                            // Visually mute disabled rows so the user can
                            // see at a glance which IDs are parked.
                            // Strike-through + reduced contrast — same
                            // pattern the SNI pool modal uses on disabled
                            // hosts.
                            MaterialTheme.typography.bodySmall.copy(
                                textDecoration = androidx.compose.ui.text.style.TextDecoration.LineThrough,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        },
                    label = { Text(stringResource(R.string.field_deployment_url_index, index + 1)) },
                )
                IconButton(
                    onClick = {
                        onChange(urls.filterIndexed { i, _ -> i != index })
                    },
                ) {
                    Text("✕", color = MaterialTheme.colorScheme.error)
                }
            }
        }

        // "Add" row: multi-line text field + button. Multi-line so a user
        // can paste a long list at once (newline-separated is the natural
        // form when copying out of the desktop UI's textarea). Newly-
        // added rows default to enabled — disabling is an explicit act.
        Row(
            verticalAlignment = Alignment.Top,
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = newEntry,
                onValueChange = { newEntry = it },
                modifier = Modifier.weight(1f),
                singleLine = false,
                minLines = 1,
                maxLines = 6,
                placeholder = { Text(stringResource(R.string.placeholder_paste_ids)) },
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = {
                    val parts = newEntry.split(ID_SEPARATORS).filter { it.isNotBlank() }
                    if (parts.isNotEmpty()) {
                        onChange(urls + parts.map { DeploymentEntry(it, true) })
                        newEntry = ""
                    }
                },
                enabled = newEntry.isNotBlank(),
                contentPadding = PaddingValues(horizontal = 12.dp),
            ) {
                Text(stringResource(R.string.btn_add_url))
            }
        }

        Text(
            stringResource(R.string.help_deployment_urls),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// =========================================================================
// Mode dropdown: apps_script (default), direct, full, or local_bypass.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ModeDropdown(
    mode: Mode,
    onChange: (Mode) -> Unit,
) {
    val labelApps = stringResource(R.string.mode_apps_script_label)
    val labelDirect = stringResource(R.string.mode_direct_label)
    val labelFull = stringResource(R.string.mode_full_label)
    val labelLocalBypass = stringResource(R.string.mode_local_bypass_label)
    val labelDrive = stringResource(R.string.mode_drive_label)
    val currentLabel =
        when (mode) {
            Mode.APPS_SCRIPT -> labelApps
            Mode.DIRECT -> labelDirect
            Mode.FULL -> labelFull
            Mode.LOCAL_BYPASS -> labelLocalBypass
            Mode.DRIVE -> labelDrive
        }
    var expanded by remember { mutableStateOf(false) }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = currentLabel,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.sec_mode)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                DropdownMenuItem(
                    text = { Text(labelApps) },
                    onClick = {
                        onChange(Mode.APPS_SCRIPT)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelDirect) },
                    onClick = {
                        onChange(Mode.DIRECT)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelFull) },
                    onClick = {
                        onChange(Mode.FULL)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelLocalBypass) },
                    onClick = {
                        onChange(Mode.LOCAL_BYPASS)
                        expanded = false
                    },
                )
                DropdownMenuItem(
                    text = { Text(labelDrive) },
                    onClick = {
                        onChange(Mode.DRIVE)
                        expanded = false
                    },
                )
            }
        }

        val help =
            when (mode) {
                Mode.APPS_SCRIPT -> stringResource(R.string.help_mode_apps_script)
                Mode.DIRECT -> stringResource(R.string.help_mode_direct)
                Mode.FULL -> stringResource(R.string.help_mode_full)
                Mode.LOCAL_BYPASS -> stringResource(R.string.help_mode_local_bypass)
                Mode.DRIVE -> stringResource(R.string.help_mode_drive)
            }
        Text(
            help,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (mode == Mode.DIRECT) {
            Text(
                stringResource(R.string.direct_upstream_help),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// =========================================================================
// SNI pool editor + per-SNI probe.
// =========================================================================

private sealed class ProbeState {
    object Idle : ProbeState()

    object InFlight : ProbeState()

    data class Ok(
        val latencyMs: Int,
    ) : ProbeState()

    data class Err(
        val message: String,
    ) : ProbeState()
}

@Composable
private fun SniPoolEditor(
    cfg: RahgozarConfig,
    onChange: (RahgozarConfig) -> Unit,
) {
    val scope = rememberCoroutineScope()

    // Build the displayed list: union of the default pool + the config's
    // sniHosts + the current front_domain. Order: front_domain first,
    // defaults, then user customs. Deduped.
    val displayed: List<String> =
        remember(cfg) {
            val seen = linkedSetOf<String>()
            if (cfg.frontDomain.isNotBlank()) seen.add(cfg.frontDomain.trim())
            DEFAULT_SNI_POOL.forEach { seen.add(it) }
            cfg.sniHosts.forEach { if (it.isNotBlank()) seen.add(it.trim()) }
            seen.toList()
        }

    // A host is enabled if it appears in cfg.sniHosts. Empty sniHosts
    // means "let Rust auto-expand" — we reflect that as "default pool
    // enabled, customs not".
    val enabledSet: Set<String> =
        remember(cfg.sniHosts) {
            if (cfg.sniHosts.isNotEmpty()) {
                cfg.sniHosts.toSet()
            } else {
                DEFAULT_SNI_POOL.toSet() + setOfNotNull(cfg.frontDomain.takeIf { it.isNotBlank() })
            }
        }

    val probeState = remember { mutableStateMapOf<String, ProbeState>() }

    fun probe(sni: String) {
        probeState[sni] = ProbeState.InFlight
        scope.launch {
            val json =
                withContext(Dispatchers.IO) {
                    runCatching { Native.testSni(cfg.googleIp, sni) }.getOrNull()
                }
            probeState[sni] = parseProbeResult(json)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(
            stringResource(R.string.help_sni_pool),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        displayed.forEach { sni ->
            val enabled = sni in enabledSet
            SniRow(
                sni = sni,
                enabled = enabled,
                state = probeState[sni] ?: ProbeState.Idle,
                onToggle = { nowEnabled ->
                    val next =
                        if (nowEnabled) {
                            (cfg.sniHosts.takeIf { it.isNotEmpty() } ?: emptyList()) + sni
                        } else {
                            val current = if (cfg.sniHosts.isNotEmpty()) cfg.sniHosts else enabledSet.toList()
                            current.filter { it != sni }
                        }
                    onChange(cfg.copy(sniHosts = next.distinct()))
                },
                onTest = { probe(sni) },
            )
        }

        // Custom-add row.
        var custom by remember { mutableStateOf("") }
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedTextField(
                value = custom,
                onValueChange = { custom = it },
                label = { Text(stringResource(R.string.field_add_custom_sni)) },
                // Accept a pasted list — users (issue #47) want to dump a
                // whole list of subdomains in one go. We split on newlines,
                // commas, semicolons, and whitespace so formats like
                //   www.google.com\nmail.google.com\ndrive.google.com
                //   www.google.com, mail.google.com
                //   www.google.com mail.google.com
                // all do the right thing on Add.
                singleLine = false,
                maxLines = 6,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier.weight(1f),
            )
            TextButton(
                onClick = {
                    // Tokenise on any whitespace, comma, or semicolon so one
                    // Add click absorbs a pasted list. Deduplicate within
                    // the paste before merging into the existing list.
                    val tokens =
                        custom
                            .split(Regex("[\\s,;]+"))
                            .map { it.trim() }
                            .filter { it.isNotEmpty() }
                    if (tokens.isNotEmpty()) {
                        val base = cfg.sniHosts.takeIf { it.isNotEmpty() } ?: enabledSet.toList()
                        val next = (base + tokens).distinct()
                        onChange(cfg.copy(sniHosts = next))
                        custom = ""
                    }
                },
                enabled = custom.isNotBlank(),
            ) { Text(stringResource(R.string.btn_add)) }
        }

        TextButton(
            onClick = { displayed.forEach { probe(it) } },
            modifier = Modifier.align(Alignment.End),
        ) { Text(stringResource(R.string.btn_test_all)) }
    }
}

@Composable
private fun SniRow(
    sni: String,
    enabled: Boolean,
    state: ProbeState,
    onToggle: (Boolean) -> Unit,
    onTest: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Checkbox(checked = enabled, onCheckedChange = onToggle)
            Text(
                sni,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.bodyMedium,
            )
            ProbeBadge(state)
            Spacer(Modifier.width(4.dp))
            TextButton(onClick = onTest, enabled = state !is ProbeState.InFlight) {
                Text(stringResource(R.string.btn_test))
            }
        }
        // Show the error reason on its own line when the probe failed —
        // a red dot with no explanation was confusing ("SNI test also
        // fails despite having internet"). Common reasons: "dns: ..." or
        // "connect: ...".
        if (state is ProbeState.Err) {
            Text(
                text = state.message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(start = 48.dp, bottom = 4.dp),
            )
        }
    }
}

@Composable
private fun ProbeBadge(state: ProbeState) {
    when (state) {
        is ProbeState.Idle -> {}

        is ProbeState.InFlight -> {
            CircularProgressIndicator(
                modifier = Modifier.size(14.dp),
                strokeWidth = 2.dp,
            )
        }

        is ProbeState.Ok -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Status-OK green from the Android palette. Used to be
                // kept in sync with the legacy desktop egui binary's
                // OK_GREEN; the desktop moved to Tauri in v2.4 and
                // Android now owns its palette independently
                // (see ui/theme/Theme.kt).
                Icon(
                    Icons.Default.CheckCircle,
                    null,
                    tint = OkGreen,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(Modifier.width(2.dp))
                Text(
                    stringResource(R.string.sni_latency_ms_fmt, state.latencyMs),
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }

        is ProbeState.Err -> {
            Icon(
                Icons.Default.ErrorOutline,
                state.message,
                tint = MaterialTheme.colorScheme.error,
                modifier = Modifier.size(16.dp),
            )
        }
    }
}

/**
 * Show the "Update available" snackbar with an `Install` action. Tapping
 * Install kicks off the full sideload flow:
 *   1. If the device is API 26+ and "Install unknown apps" isn't yet
 *      granted for us, route the user to that settings page (single
 *      one-time tap by the user — Android remembers the choice). After
 *      they grant it, they tap the version label again to retry.
 *   2. Download and verify the per-ABI APK via `Native.downloadAsset`
 *      (rustls + minisign when the build embeds an update public key).
 *   3. Hand the APK to the OS installer; the user confirms the install
 *      in the standard "Update existing app?" dialog. After install the
 *      OS replaces our process — no callback, but the new build launches
 *      from the home screen icon as normal.
 *
 * If the API response didn't include an `assetUrl` (e.g. the user is on
 * an unsupported ABI, or the release didn't ship a per-ABI APK we
 * recognise) we fall back to a plain message with the release URL.
 */
private fun offerInstall(
    ctx: android.content.Context,
    scope: kotlinx.coroutines.CoroutineScope,
    snackbar: SnackbarHostState,
    state: UpdateInstaller.State.Available,
) {
    scope.launch {
        // Drop the call if another offer/download/install is already in
        // flight. Without this, repeated taps on the version button (with
        // the badge cached) queue duplicate coroutines that race inside
        // `downloadApk` — which wipes the updates cache dir before writing.
        if (!UpdateInstaller.tryAcquireOffer()) return@launch
        try {
            val asset = state.asset
            if (asset == null) {
                snackbar.showSnackbar(
                    ctx.getString(
                        R.string.snack_update_available_url,
                        state.current,
                        state.latest,
                        state.releaseUrl,
                    ),
                    withDismissAction = true,
                )
                return@launch
            }

            val msg =
                ctx.getString(
                    R.string.snack_update_available,
                    state.current,
                    state.latest,
                )
            val result =
                snackbar.showSnackbar(
                    message = msg,
                    actionLabel = ctx.getString(R.string.btn_install),
                    withDismissAction = true,
                    duration = SnackbarDuration.Indefinite,
                )
            if (result != SnackbarResult.ActionPerformed) return@launch

            if (!UpdateInstaller.canInstallUnknownApps(ctx)) {
                UpdateInstaller.openUnknownSourcesSettings(ctx)
                snackbar.showSnackbar(
                    ctx.getString(R.string.snack_update_enable_unknown_apps),
                    withDismissAction = true,
                )
                return@launch
            }

            // `showSnackbar` is a suspend fun that suspends until the snackbar
            // is dismissed or replaced. With Indefinite + no action button +
            // no dismiss button, the only way to release that suspension is
            // a sibling coroutine cancelling/replacing it — running the
            // download on the same coroutine would deadlock here.
            val snackJob =
                scope.launch {
                    snackbar.showSnackbar(
                        ctx.getString(
                            R.string.snack_update_downloading,
                            asset.sizeBytes.toDouble() / 1_048_576.0,
                        ),
                        withDismissAction = false,
                        duration = SnackbarDuration.Indefinite,
                    )
                }
            val dl =
                try {
                    UpdateInstaller.downloadApk(ctx, asset)
                } finally {
                    snackJob.cancel()
                }
            when (dl) {
                is UpdateInstaller.State.ReadyToInstall -> {
                    runCatching { UpdateInstaller.launchInstaller(ctx, dl.apk) }
                        .onSuccess {
                            // OS installer is now showing the "Update existing
                            // app?" dialog — the user has clearly seen the
                            // update, so drop the badge. Stale-but-cleared is
                            // better than stuck-on after they cancel the OS
                            // dialog; if they want it back, the version-button
                            // tap re-checks fresh.
                            UpdateInstaller.clearPendingUpdate()
                        }.onFailure {
                            snackbar.showSnackbar(
                                ctx.getString(
                                    R.string.snack_update_open_installer_failed,
                                    it.message ?: "",
                                ),
                                withDismissAction = true,
                            )
                        }
                }

                is UpdateInstaller.State.Failed -> {
                    snackbar.showSnackbar(dl.reason, withDismissAction = true)
                }

                else -> { /* unreachable for downloadApk's return type */ }
            }
        } finally {
            UpdateInstaller.releaseOffer()
        }
    }
}

/**
 * Turn the JSON blob from `Native.checkUpdate()` into a one-line
 * snackbar message. Parsing is lenient — if the shape is anything other
 * than what we expect we fall back to "check failed" rather than
 * spewing the raw JSON at the user.
 */
private fun summarizeUpdateCheck(json: String?): String {
    if (json.isNullOrBlank()) return "Update check failed (no response)"
    return try {
        val obj = JSONObject(json)
        when (obj.optString("kind")) {
            "upToDate" -> {
                "Up to date (running v${obj.optString("current")})"
            }

            "updateAvailable" -> {
                val cur = obj.optString("current")
                val latest = obj.optString("latest")
                val url = obj.optString("url")
                "Update available: v$cur → v$latest   $url"
            }

            "offline" -> {
                "Offline: ${obj.optString("reason", "no details")}"
            }

            "error" -> {
                "Check failed: ${obj.optString("reason", "no details")}"
            }

            else -> {
                "Check failed (unknown response)"
            }
        }
    } catch (_: Throwable) {
        "Check failed (bad json)"
    }
}

/**
 * Try to parse a string as an IPv4 or IPv6 literal. Returns null if it
 * looks like a hostname (or bogus) — which is what we want for
 * front_domain, where a hostname is required (goes into the TLS SNI on
 * the outbound leg).
 *
 * Intentionally strict: must be a valid literal AND must not contain a
 * letter anywhere. Plain `InetAddress.getByName(...)` would succeed for
 * hostnames too (it'd do a DNS lookup and return an IP), which would
 * false-positive every normal value like "www.google.com".
 */
private fun String.parseAsIpOrNull(): java.net.InetAddress? {
    val s = trim()
    if (s.isEmpty() || s.any { it.isLetter() }) return null
    return try {
        // Literal-only parse: rejects anything that would need DNS.
        java.net.InetAddress.getByName(s).takeIf {
            it.hostAddress?.let { addr -> addr == s || addr.contains(s) } == true
        }
    } catch (_: Throwable) {
        null
    }
}

private fun parseProbeResult(json: String?): ProbeState {
    if (json.isNullOrBlank()) return ProbeState.Err("no response")
    return try {
        val obj = JSONObject(json)
        if (obj.optBoolean("ok", false)) {
            ProbeState.Ok(obj.optInt("latencyMs", -1))
        } else {
            ProbeState.Err(obj.optString("error", "failed"))
        }
    } catch (_: Throwable) {
        ProbeState.Err("bad json")
    }
}

// =========================================================================
// CDN fronting groups editor + discover-by-hostname.
// =========================================================================

/**
 * Result of one "Discover front" call against `Native.discoverFront()`.
 *
 * `internal` rather than `private` so the JVM unit-test module under
 * `app/src/test/` can reach in and assert against the parsed shape.
 * The class is otherwise a UI-only ephemeral state container.
 */
internal sealed class DiscoverState {
    object Idle : DiscoverState()

    /** Probe is running. Kept so the UI can show "Discovering <hostname>…". */
    data class InFlight(
        val hostname: String,
    ) : DiscoverState()

    /** Top-level failure (bad input, DNS timeout, etc.). */
    data class Error(
        val hostname: String,
        val message: String,
    ) : DiscoverState()

    /** DNS resolved; per-IP probe results follow. */
    data class Done(
        val hostname: String,
        val ips: List<DiscoveredIp>,
    ) : DiscoverState()
}

/** One probed IP from a `DiscoverState.Done`. `internal` for the same reason. */
internal data class DiscoveredIp(
    val ip: String,
    val ok: Boolean,
    val latencyMs: Int?,
    val error: String?,
)

/**
 * Parse the JSON blob returned by `Native.discoverFront()`. Shape is
 * documented on the Native binding — `ok=true` rows carry `latencyMs`,
 * `ok=false` rows carry `error`. Top-level `error` field means the
 * resolve itself failed (bad input, DNS timeout); in that case `ips`
 * is absent and we return Error.
 *
 * `internal` for testability (see DiscoverState).
 */
internal fun parseDiscoverResult(json: String?): DiscoverState {
    if (json.isNullOrBlank()) {
        return DiscoverState.Error("", "no response from native layer")
    }
    return try {
        val obj = JSONObject(json)
        val hostname = obj.optString("hostname", "")
        val topErr = obj.optString("error", "")
        if (topErr.isNotBlank()) {
            return DiscoverState.Error(hostname, topErr)
        }
        val arr = obj.optJSONArray("ips") ?: return DiscoverState.Error(hostname, "no ips in response")
        val ips =
            buildList {
                for (i in 0 until arr.length()) {
                    val r = arr.optJSONObject(i) ?: continue
                    val ip = r.optString("ip", "")
                    if (ip.isBlank()) continue
                    val ok = r.optBoolean("ok", false)
                    val latency = if (r.has("latencyMs")) r.optInt("latencyMs") else null
                    val err = r.optString("error", "").takeIf { it.isNotBlank() }
                    add(DiscoveredIp(ip = ip, ok = ok, latencyMs = latency, error = err))
                }
            }
        DiscoverState.Done(hostname, ips)
    } catch (t: Throwable) {
        DiscoverState.Error("", t.message ?: "parse failed")
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FrontingGroupsEditor(
    cfg: RahgozarConfig,
    onChange: (RahgozarConfig) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val ctx = LocalContext.current
    var hostname by rememberSaveable { mutableStateOf("") }
    var discover by remember { mutableStateOf<DiscoverState>(DiscoverState.Idle) }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            stringResource(R.string.fronting_help),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // Existing groups list — each row is name + ip via sni, a domains
        // editor below, and a remove button. Persisted via onChange after
        // every edit so a backgrounded app doesn't lose unsaved changes.
        cfg.frontingGroups.forEachIndexed { idx, g ->
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.surfaceVariant,
                            RoundedCornerShape(8.dp),
                        ).padding(8.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        g.name,
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.weight(1f),
                    )
                    // Camouflage (force_ip) groups have no editable edge IP
                    // — the destination IP is DoH-resolved at runtime and
                    // the SNI is a decoy. Flag them so the empty IP below
                    // doesn't read as a misconfiguration.
                    if (g.forceIp) {
                        Text(
                            stringResource(R.string.fronting_group_camouflage_badge),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier =
                                Modifier
                                    .background(
                                        MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                                        RoundedCornerShape(4.dp),
                                    ).padding(horizontal = 6.dp, vertical = 2.dp),
                        )
                    }
                    TextButton(
                        onClick = {
                            val next = cfg.frontingGroups.toMutableList().apply { removeAt(idx) }
                            onChange(cfg.copy(frontingGroups = next))
                        },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) {
                        Text(stringResource(R.string.btn_remove_group), color = ErrRed)
                    }
                }
                Text(
                    if (g.forceIp) {
                        stringResource(R.string.fronting_group_camouflage_detail, g.sni)
                    } else {
                        "${g.ip}  via  ${g.sni}"
                    },
                    style =
                        MaterialTheme.typography.labelSmall.copy(
                            fontFamily = FontFamily.Monospace,
                        ),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Draft warning: surface that Save will drop this group so
                // the user doesn't think it'll persist. Matches the filter
                // in ConfigStore.toJson().
                val hasDomains = g.domains.any { it.isNotBlank() }
                if (!hasDomains) {
                    Text(
                        stringResource(R.string.fronting_group_draft_warning),
                        style = MaterialTheme.typography.labelSmall,
                        color = ErrRed,
                    )
                }
                // Domains edited as one newline-separated text field. Split
                // on every change so the persisted form stays canonical and
                // the user can also paste a comma-separated list if they
                // want — both separators are accepted on save.
                var domainsText by remember(g.domains) {
                    mutableStateOf(g.domains.joinToString("\n"))
                }
                OutlinedTextField(
                    value = domainsText,
                    onValueChange = { v ->
                        domainsText = v
                        val parsed =
                            v
                                .split('\n', ',')
                                .map { it.trim() }
                                .filter { it.isNotEmpty() }
                        val next =
                            cfg.frontingGroups.toMutableList().apply {
                                this[idx] = g.copy(domains = parsed)
                            }
                        onChange(cfg.copy(frontingGroups = next))
                    },
                    placeholder = { Text(stringResource(R.string.fronting_hint_domains)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                )
                // CDN-edge mismatch warning: domains here are routed to
                // g.ip with SNI=g.sni; misconfigured entries leak the
                // inner Host to the wrong backend. See
                // docs/fronting-groups.md.
                Text(
                    stringResource(R.string.fronting_edge_mismatch_warning),
                    style = MaterialTheme.typography.labelSmall,
                    color =
                        androidx.compose.ui.graphics
                            .Color(0xFFDCB464),
                )
            }
        }

        // Discover-by-hostname row.
        OutlinedTextField(
            value = hostname,
            onValueChange = { hostname = it },
            label = { Text(stringResource(R.string.fronting_hint_hostname)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        val inFlight = discover is DiscoverState.InFlight
        Button(
            onClick = {
                val h = hostname.trim()
                if (h.isEmpty()) return@Button
                discover = DiscoverState.InFlight(h)
                scope.launch {
                    val json =
                        withContext(Dispatchers.IO) {
                            runCatching { Native.discoverFront(h) }.getOrNull()
                        }
                    discover = parseDiscoverResult(json)
                }
            },
            enabled = !inFlight && hostname.isNotBlank(),
            modifier = Modifier.align(Alignment.End),
        ) {
            Text(
                if (inFlight) {
                    stringResource(R.string.btn_discovering)
                } else {
                    stringResource(R.string.btn_discover)
                },
            )
        }

        // Discover result panel.
        when (val s = discover) {
            is DiscoverState.Idle -> {
                Unit
            }

            is DiscoverState.InFlight -> {
                Text(
                    stringResource(R.string.fronting_discovering_fmt, s.hostname),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            is DiscoverState.Error -> {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(R.string.fronting_result_error_fmt, s.hostname, s.message),
                        style = MaterialTheme.typography.labelSmall,
                        color = ErrRed,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = { discover = DiscoverState.Idle },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) { Text(stringResource(R.string.btn_dismiss)) }
                }
            }

            is DiscoverState.Done -> {
                val okCount = s.ips.count { it.ok }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        if (okCount > 0) {
                            stringResource(
                                R.string.fronting_result_ok_fmt,
                                s.hostname,
                                okCount,
                                s.ips.size,
                            )
                        } else {
                            stringResource(R.string.fronting_result_none_fmt, s.hostname)
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = if (okCount > 0) OkGreen else ErrRed,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = { discover = DiscoverState.Idle },
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                    ) { Text(stringResource(R.string.btn_dismiss)) }
                }
                s.ips.forEach { r ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        val marker = if (r.ok) "✓" else "✗"
                        val color = if (r.ok) OkGreen else ErrRed
                        Text(marker, color = color)
                        Spacer(Modifier.width(6.dp))
                        Text(
                            r.ip,
                            style =
                                MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                ),
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            when {
                                r.ok && r.latencyMs != null -> {
                                    stringResource(R.string.fronting_latency_ms_fmt, r.latencyMs)
                                }

                                else -> {
                                    r.error ?: ""
                                }
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                        )
                        if (r.ok) {
                            TextButton(
                                onClick = {
                                    // Pick a unique name to avoid log-line
                                    // ambiguity (proxy_server warns on dup
                                    // group names).
                                    val base = s.hostname
                                    val existing = cfg.frontingGroups.map { it.name }.toSet()
                                    val name =
                                        if (base !in existing) {
                                            base
                                        } else {
                                            var n = 2
                                            var candidate = "$base-$n"
                                            while (candidate in existing) {
                                                n++
                                                candidate = "$base-$n"
                                            }
                                            candidate
                                        }
                                    val next =
                                        cfg.frontingGroups +
                                            FrontingGroup(
                                                name = name,
                                                ip = r.ip,
                                                sni = s.hostname,
                                                domains = emptyList(),
                                            )
                                    onChange(cfg.copy(frontingGroups = next))
                                    Toast
                                        .makeText(
                                            ctx,
                                            ctx.getString(R.string.fronting_group_added_fmt, s.hostname),
                                            Toast.LENGTH_SHORT,
                                        ).show()
                                    hostname = ""
                                    discover = DiscoverState.Idle
                                },
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp),
                            ) {
                                Text(
                                    stringResource(R.string.btn_add_as_group),
                                    style = MaterialTheme.typography.labelSmall,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// =========================================================================
// Advanced settings.
// =========================================================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdvancedSettings(
    cfg: RahgozarConfig,
    onChange: (RahgozarConfig) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        // verify_ssl
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.adv_verify_tls), style = MaterialTheme.typography.bodyMedium)
                Text(
                    stringResource(R.string.adv_verify_tls_help),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.verifySsl,
                onCheckedChange = { onChange(cfg.copy(verifySsl = it)) },
            )
        }

        // youtube_via_relay
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.adv_youtube_via_relay), style = MaterialTheme.typography.bodyMedium)
                Text(
                    stringResource(R.string.adv_youtube_via_relay_help),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.youtubeViaRelay,
                onCheckedChange = { onChange(cfg.copy(youtubeViaRelay = it)) },
            )
        }

        // log_level dropdown
        var expanded by remember { mutableStateOf(false) }
        val levels = listOf("trace", "debug", "info", "warn", "error", "off")
        ExposedDropdownMenuBox(
            expanded = expanded,
            onExpandedChange = { expanded = !expanded },
        ) {
            OutlinedTextField(
                value = cfg.logLevel,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.adv_log_level)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
                modifier = Modifier.fillMaxWidth().menuAnchor(),
            )
            ExposedDropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                levels.forEach { lvl ->
                    DropdownMenuItem(
                        text = { Text(lvl) },
                        onClick = {
                            onChange(cfg.copy(logLevel = lvl))
                            expanded = false
                        },
                    )
                }
            }
        }

        // parallel_relay slider
        Column {
            Text(
                stringResource(R.string.adv_parallel_relay, cfg.parallelRelay),
                style = MaterialTheme.typography.bodyMedium,
            )
            Slider(
                value = cfg.parallelRelay.toFloat(),
                onValueChange = { onChange(cfg.copy(parallelRelay = it.toInt().coerceIn(1, 5))) },
                valueRange = 1f..5f,
                steps = 3, // yields 1,2,3,4,5 positions
            )
            Text(
                stringResource(R.string.adv_parallel_relay_help),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Block QUIC toggle
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.adv_block_quic),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.adv_block_quic_help),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.blockQuic,
                onCheckedChange = { onChange(cfg.copy(blockQuic = it)) },
            )
        }

        // Block STUN/TURN toggle
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    "Block STUN/TURN",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    "Reject STUN/TURN ports (3478/5349/19302). Forces WebRTC apps (Meet, WhatsApp) to TCP fallback — instant connect.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.blockStun,
                onCheckedChange = { onChange(cfg.copy(blockStun = it)) },
            )
        }

        // Block DoH toggle
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.adv_block_doh),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.adv_block_doh_help),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = cfg.blockDoh,
                onCheckedChange = { onChange(cfg.copy(blockDoh = it)) },
            )
        }

        // Bypass DoH toggle
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    stringResource(R.string.adv_bypass_doh),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    stringResource(R.string.adv_bypass_doh_help),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(
                checked = !cfg.tunnelDoh,
                onCheckedChange = { onChange(cfg.copy(tunnelDoh = !it)) },
                enabled = !cfg.blockDoh,
            )
        }

        // Batch coalesce step slider
        Column {
            Text(
                "Coalesce step: ${cfg.coalesceStepMs}ms",
                style = MaterialTheme.typography.bodyMedium,
            )
            Slider(
                value = cfg.coalesceStepMs.toFloat(),
                onValueChange = { onChange(cfg.copy(coalesceStepMs = it.toInt().coerceIn(10, 500))) },
                valueRange = 10f..500f,
            )
        }

        // Batch coalesce max slider
        Column {
            Text(
                "Coalesce max: ${cfg.coalesceMaxMs}ms",
                style = MaterialTheme.typography.bodyMedium,
            )
            Slider(
                value = cfg.coalesceMaxMs.toFloat(),
                onValueChange = { onChange(cfg.copy(coalesceMaxMs = it.toInt().coerceIn(100, 2000))) },
                valueRange = 100f..2000f,
            )
        }

        OutlinedTextField(
            value = cfg.upstreamSocks5,
            onValueChange = { onChange(cfg.copy(upstreamSocks5 = it)) },
            label = { Text(stringResource(R.string.adv_upstream_socks5)) },
            placeholder = { Text(stringResource(R.string.placeholder_host_port)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            supportingText = {
                Text(stringResource(R.string.adv_upstream_socks5_help))
            },
        )

        // Curated fronting-group loader. The bundle ships at
        // assets/fronting-groups/curated.json (synced from the Rust
        // crate's canonical copy by Gradle's syncFrontingGroupsAssets
        // task). Mirrors the desktop UI's Advanced-section button.
        // No in-app editor for the entries — this is the no-typing
        // path. Existing groups with the same `name` are preserved.
        val ctx = LocalContext.current
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                stringResource(R.string.adv_fronting_groups_count, cfg.frontingGroups.size),
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                stringResource(R.string.adv_fronting_groups_help),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            FilledTonalButton(
                onClick = {
                    val curated = CuratedGroups.loadCurated(ctx)
                    if (curated == null) {
                        Toast
                            .makeText(
                                ctx,
                                ctx.getString(R.string.toast_curated_load_failed),
                                Toast.LENGTH_LONG,
                            ).show()
                    } else {
                        val (merged, report) = CuratedGroups.mergeInto(cfg.frontingGroups, curated)
                        onChange(cfg.copy(frontingGroups = merged))
                        Toast
                            .makeText(
                                ctx,
                                ctx.getString(
                                    R.string.toast_curated_loaded,
                                    report.added,
                                    report.skipped,
                                ),
                                Toast.LENGTH_LONG,
                            ).show()
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.btn_load_curated_groups))
            }
        }
    }
}

// =========================================================================
// Live log pane — polls Native.drainLogs() on a 500ms tick.
// =========================================================================

@Composable
private fun LiveLogPane() {
    val lines = remember { mutableStateListOf<String>() }
    val listState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val ctx = LocalContext.current

    // Pull from the ring buffer periodically. We pull even while the
    // section is collapsed (cheap), so re-expanding shows fresh tail.
    LaunchedEffect(Unit) {
        while (true) {
            val blob =
                withContext(Dispatchers.IO) {
                    runCatching { Native.drainLogs() }.getOrNull()
                }
            if (!blob.isNullOrEmpty()) {
                blob.split("\n").forEach { if (it.isNotBlank()) lines.add(it) }
                // Cap the visible list so we don't grow unboundedly.
                while (lines.size > 500) lines.removeAt(0)
                // Follow tail.
                if (lines.isNotEmpty()) {
                    listState.scrollToItem(lines.size - 1)
                }
            }
            delay(500)
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${lines.size} lines",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f),
            )
            TextButton(
                enabled = lines.isNotEmpty(),
                onClick = {
                    clipboard.setText(AnnotatedString(lines.joinToString("\n")))
                    Toast
                        .makeText(
                            ctx,
                            ctx.getString(R.string.snack_logs_copied),
                            Toast.LENGTH_SHORT,
                        ).show()
                },
            ) { Text(stringResource(R.string.btn_copy)) }
            TextButton(onClick = { lines.clear() }) { Text(stringResource(R.string.btn_clear)) }
        }
        Surface(
            color = MaterialTheme.colorScheme.surfaceVariant,
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp, max = 320.dp),
        ) {
            // SelectionContainer makes log lines selectable for manual
            // copy of partial ranges. Cross-line selection works within the
            // currently rendered window; for "copy everything" the Copy
            // button above is the reliable path.
            SelectionContainer {
                LazyColumn(
                    state = listState,
                    modifier = Modifier.padding(8.dp),
                ) {
                    items(lines) { line ->
                        Text(
                            line,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        )
                    }
                }
            }
        }
    }
}

// =========================================================================
// Small shared pieces.
// =========================================================================

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleMedium,
    )
}

/**
 * Minimal disclosure widget. Compose has no stock "expandable card" in
 * Material3 yet, so we build it from a clickable header + AnimatedVisibility
 * wrapping the content.
 */
@Composable
internal fun CollapsibleSection(
    title: String,
    initiallyExpanded: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    var expanded by rememberSaveable(title) { mutableStateOf(initiallyExpanded) }
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                )
                TextButton(onClick = { expanded = !expanded }) {
                    Icon(
                        if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                        contentDescription = if (expanded) "Collapse" else "Expand",
                    )
                }
            }
            AnimatedVisibility(visible = expanded) {
                Column(
                    modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    content = content,
                )
            }
        }
    }
}

/**
 * "Usage today (estimated)" card. Polls `Native.statsJson(handle)` every
 * second while the proxy is up and renders today's relay calls vs. the
 * Apps Script free-tier quota (20,000/day), today's bytes, the Pacific
 * Time day key, and a countdown to the 00:00 PT reset. Pacific Time
 * matches Apps Script's actual quota reset cadence — UTC would have
 * the counter resetting ~7-8 h before the user actually got a fresh
 * quota allotment from Google. Also shows a "View quota on Google"
 * button that opens Google's Apps Script dashboard — the authoritative
 * number, since the client-side estimate only sees what this device
 * relayed.
 *
 * Hidden when the handle is 0 (proxy not running) or the JSON comes back
 * empty (direct / full-only configs don't run a DomainFronter and so
 * have nothing to report).
 */
@Composable
private fun UsageTodayCard() {
    // Free-tier Apps Script UrlFetchApp daily quota. Workspace / paid
    // tiers get 100k but most users are on free.
    val freeQuotaPerDay = 20_000

    val handle by VpnStateSync.proxyHandle.collectAsState()
    val isRunning by VpnStateSync.isRunning.collectAsState()

    // Nothing to poll until the proxy is up.
    if (!isRunning || handle == 0L) return

    // The service (in the `:vpn` process) pushes the stats blob via
    // broadcast on its own ticker — calling `Native.statsJson` from
    // this UI process wouldn't see a live handle anyway (the proxy's
    // tokio runtime lives only in the service process). Observe the
    // synced snapshot here instead of polling Native ourselves.
    val statsJson by VpnStateSync.statsJson.collectAsState()

    val obj =
        remember(statsJson) {
            if (statsJson.isBlank()) {
                null
            } else {
                runCatching { JSONObject(statsJson) }.getOrNull()
            }
        }
    // Still booting / not an apps-script config — stay silent.
    if (obj == null) return

    val todayCalls = obj.optLong("today_calls", 0L)
    val todayBytes = obj.optLong("today_bytes", 0L)
    val todayKey = obj.optString("today_key", "")
    val resetSecs = obj.optLong("today_reset_secs", 0L)
    val pct =
        if (freeQuotaPerDay > 0) {
            (todayCalls.toDouble() / freeQuotaPerDay) * 100.0
        } else {
            0.0
        }

    val ctx = LocalContext.current

    Spacer(Modifier.height(8.dp))
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                stringResource(R.string.sec_usage_today),
                style = MaterialTheme.typography.titleSmall,
            )

            UsageRow(
                label = stringResource(R.string.label_calls_today),
                value =
                    stringResource(
                        R.string.usage_calls_of_quota,
                        todayCalls.toInt(),
                        freeQuotaPerDay,
                        pct,
                    ),
            )
            UsageRow(
                label = stringResource(R.string.label_bytes_today),
                value = fmtBytes(todayBytes),
            )
            UsageRow(
                label = stringResource(R.string.label_pt_day),
                value = todayKey,
            )
            UsageRow(
                label = stringResource(R.string.label_resets_in),
                value =
                    stringResource(
                        R.string.usage_resets_hm,
                        (resetSecs / 3600).toInt(),
                        ((resetSecs / 60) % 60).toInt(),
                    ),
            )

            Spacer(Modifier.height(4.dp))
            TextButton(
                onClick = {
                    // Open the Google-side Apps Script quota dashboard in
                    // the user's browser. Uses ACTION_VIEW with a https://
                    // URI — the OS picks whatever default browser is set.
                    val intent =
                        android.content.Intent(
                            android.content.Intent.ACTION_VIEW,
                            android.net.Uri.parse("https://script.google.com/home/usage"),
                        )
                    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    runCatching { ctx.startActivity(intent) }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(stringResource(R.string.btn_view_quota_on_google))
            }
            Text(
                stringResource(R.string.usage_today_note),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun UsageRow(
    label: String,
    value: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
    }
}

@Composable
private fun PipelineDebugCard() {
    val isRunning by VpnStateSync.isRunning.collectAsState()
    if (!isRunning) return

    // Same rationale as UsageTodayCard: the service process is the
    // only one with a live tokio runtime + pipeline_debug counters,
    // so we observe the rebroadcast snapshot rather than poll Native
    // from the UI process (which would return an empty blob anyway).
    val json by VpnStateSync.pipelineJson.collectAsState()

    val obj =
        remember(json) {
            if (json.isBlank()) {
                null
            } else {
                runCatching { JSONObject(json) }.getOrNull()
            }
        }
    if (obj == null) return

    val elevated = obj.optInt("elevated", 0)
    val maxElevated = obj.optInt("max_elevated", 0)
    val batches = obj.optInt("active_batches", 0)
    val maxBatches = obj.optInt("max_batch_slots", 0)
    val events =
        remember(json) {
            val arr = obj.optJSONArray("events") ?: return@remember emptyList<String>()
            (0 until arr.length()).map { arr.getString(it) }
        }

    Spacer(Modifier.height(8.dp))
    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                stringResource(R.string.debug_pipeline_title),
                style = MaterialTheme.typography.titleSmall,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(stringResource(R.string.debug_elevated), style = MaterialTheme.typography.bodySmall)
                Text(
                    "$elevated / $maxElevated",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(stringResource(R.string.debug_batches_inflight), style = MaterialTheme.typography.bodySmall)
                Text(
                    "$batches / $maxBatches",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
            if (events.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text(stringResource(R.string.debug_events), style = MaterialTheme.typography.labelSmall)
                Box(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .heightIn(max = 150.dp)
                            .clip(RoundedCornerShape(4.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .padding(6.dp),
                ) {
                    val listState = rememberLazyListState()
                    LaunchedEffect(events.size) {
                        if (events.isNotEmpty()) listState.animateScrollToItem(events.size - 1)
                    }
                    LazyColumn(state = listState) {
                        items(events) { ev ->
                            Text(
                                ev,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun fmtBytes(b: Long): String {
    val k = 1024L
    val m = k * k
    val g = m * k
    return when {
        b >= g -> String.format("%.2f GB", b.toDouble() / g)
        b >= m -> String.format("%.2f MB", b.toDouble() / m)
        b >= k -> String.format("%.1f KB", b.toDouble() / k)
        else -> "$b B"
    }
}

@Composable
private fun HowToUseBody(listenPort: Int) {
    // Used inside the collapsible "How to use" CollapsibleSection. The
    // card + title are provided by the section wrapper, so this body
    // just renders the body text.
    //
    // Text is sourced from string resources (values/strings.xml +
    // values-fa/strings.xml) so the Persian locale gets a translated
    // guide instead of falling back to English.
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = stringResource(R.string.help_how_to_use),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
