package com.dazzlingnomore.mhrv.ui

// Drive-mode setup section. Lives next to HomeScreen.kt (same
// `com.dazzlingnomore.mhrv.ui` package, no import needed at the call
// site). Owns the entire OAuth/folder-create/test surface as a
// self-contained Compose component.
//
// OAuth flow on Android (RFC 8628 device-code):
//   1. User taps "Sign in with Google".
//   2. Coroutine calls `Native.driveOauthDeviceCodeStart()` ->
//      `{flow_token, user_code, verification_url, interval_secs}`.
//      Rust side POSTed `/device/code` to Google and stashed the
//      opaque `device_code` against `flow_token` in an in-memory
//      registry.
//   3. UI shows a dialog with the `user_code` + `verification_url`
//      + Copy and Open-in-browser buttons. The user opens the URL
//      on any device (often the same phone in another tab), enters
//      the code, signs in.
//   4. While the dialog is up, a LaunchedEffect polls
//      `Native.driveOauthPollFlow(flow_token)` every `interval_secs`.
//      Each call hits Google's `/token` endpoint. Outcomes:
//        - "pending"    -> keep polling
//        - "slow_down"  -> bump interval by 5 s per RFC 8628 §3.5
//        - "ok"         -> refresh_token already persisted to
//                          config.json; reload + dismiss dialog
//        - "transient_error" -> keep polling after a retryable error
//        - "denied" / "expired" / "error"  -> toast + dismiss
//   5. Tapping Cancel calls `Native.driveOauthCancelFlow(flow_token)`
//      and dismisses the dialog.
//
// Android uses device-code OAuth. Use a Google OAuth client whose
// application type is "TVs and Limited Input devices" for Android /
// relay; desktop loopback PKCE uses a Desktop app client.

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.dazzlingnomore.mhrv.ConfigStore
import com.dazzlingnomore.mhrv.Native
import com.dazzlingnomore.mhrv.R
import com.dazzlingnomore.mhrv.RahgozarConfig
import com.dazzlingnomore.mhrv.ui.theme.ErrRed
import com.dazzlingnomore.mhrv.ui.theme.OkGreen
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
internal fun DriveSetupSection(
    cfg: RahgozarConfig,
    onChange: (RahgozarConfig) -> Unit,
) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    // Folder-create runs a Drive REST call that can take seconds.
    // Any coroutine that mutates cfg after a suspension point must
    // read this State (not the captured `cfg` parameter) so a
    // recomposition with edits the user made in the meantime
    // doesn't get clobbered by a stale copy.
    val latestCfg by rememberUpdatedState(cfg)

    // Device-code OAuth flow state. `activeFlow` is non-null while
    // the user has the device-code dialog up; the polling
    // LaunchedEffect runs only while it's set.
    var activeFlow by remember { mutableStateOf<DeviceCodeFlow?>(null) }
    var signingIn by remember { mutableStateOf(false) }

    // Folder-create dialog state.
    var showCreateFolderDialog by remember { mutableStateOf(false) }
    var newFolderName by remember { mutableStateOf("rahgozar mailbox") }
    var creatingFolder by remember { mutableStateOf(false) }

    // Relay pubkey live-validation state. Cached so an unchanged
    // value does not re-call the JNI on every composition. The JNI
    // call itself is pure (bech32m parse) so the cost is trivial,
    // but the cache keeps the IPC volume sane.
    var pubkeyValidation by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var pubkeyLastValidated by remember { mutableStateOf("") }

    // Test-connection state.
    var testingConnection by remember { mutableStateOf(false) }
    var lastTestResult by remember { mutableStateOf<String?>(null) }

    // Re-validate the relay pubkey whenever the field changes.
    LaunchedEffect(cfg.driveRelayPubkey) {
        val s = cfg.driveRelayPubkey.trim()
        if (s.isEmpty()) {
            pubkeyValidation = null
            pubkeyLastValidated = ""
            return@LaunchedEffect
        }
        if (s == pubkeyLastValidated) return@LaunchedEffect
        pubkeyLastValidated = s
        val errMsg = withContext(Dispatchers.IO) { Native.driveValidateRelayPubkey(s) }
        pubkeyValidation = if (errMsg.isEmpty()) Pair(true, "") else Pair(false, errMsg)
    }

    // Poll the device-code flow while the dialog is up. RFC 8628
    // §3.5 polling rules: honour the server-side `interval_secs` and
    // bump by ≥5 s on every `slow_down`. Deadline is the
    // `expires_in_secs` Google returned at flow start (1800 s
    // typical); the LaunchedEffect re-runs from the top whenever
    // `activeFlow.flowToken` changes (i.e. a fresh flow is started)
    // so a cancel + restart works cleanly.
    LaunchedEffect(activeFlow?.flowToken) {
        val flow = activeFlow ?: return@LaunchedEffect
        var intervalMs = flow.intervalSecs * 1_000L
        val deadline = System.currentTimeMillis() + flow.expiresInSecs * 1_000L
        while (System.currentTimeMillis() < deadline) {
            delay(intervalMs)
            // Re-read activeFlow at the top of each tick so a Cancel
            // (which sets activeFlow = null) breaks the loop without
            // racing the in-flight JNI call.
            if (activeFlow?.flowToken != flow.flowToken) return@LaunchedEffect
            val resp =
                withContext(Dispatchers.IO) { Native.driveOauthPollFlow(flow.flowToken) }
            val (status, errMsg, slowDownInterval) =
                try {
                    val j = JSONObject(resp)
                    Triple(
                        j.optString("status", "unknown"),
                        j.optString("error", ""),
                        j.optInt("interval_secs", 0),
                    )
                } catch (_: Throwable) {
                    Triple("unknown", "parse error", 0)
                }
            when (status) {
                "pending" -> {
                    // Keep polling at the same interval.
                }

                "slow_down" -> {
                    // RFC 8628 §3.5: bump the poll interval. Server
                    // hints at an amount via `interval_secs`; if it
                    // doesn't, add 5 s ourselves.
                    intervalMs += (slowDownInterval.coerceAtLeast(5) * 1_000L)
                }

                "ok" -> {
                    val fresh = ConfigStore.load(ctx)
                    onChange(fresh)
                    Toast
                        .makeText(ctx, ctx.getString(R.string.drive_signed_in), Toast.LENGTH_SHORT)
                        .show()
                    activeFlow = null
                    signingIn = false
                    return@LaunchedEffect
                }

                "denied" -> {
                    Toast
                        .makeText(
                            ctx,
                            ctx.getString(R.string.drive_oauth_denied),
                            Toast.LENGTH_LONG,
                        ).show()
                    activeFlow = null
                    signingIn = false
                    return@LaunchedEffect
                }

                "expired" -> {
                    Toast
                        .makeText(
                            ctx,
                            ctx.getString(R.string.drive_oauth_expired),
                            Toast.LENGTH_LONG,
                        ).show()
                    activeFlow = null
                    signingIn = false
                    return@LaunchedEffect
                }

                "transient_error" -> {
                    // JNI leaves the native flow alive for retryable
                    // transport / parse failures. Keep the dialog open
                    // and poll again on the next tick.
                    if (errMsg.isNotBlank()) {
                        Toast
                            .makeText(
                                ctx,
                                ctx.getString(R.string.drive_oauth_retrying, errMsg),
                                Toast.LENGTH_SHORT,
                            ).show()
                    }
                    intervalMs = intervalMs.coerceAtLeast(5_000L)
                }

                "error" -> {
                    Toast
                        .makeText(
                            ctx,
                            ctx.getString(R.string.drive_oauth_failed, errMsg),
                            Toast.LENGTH_LONG,
                        ).show()
                    activeFlow = null
                    signingIn = false
                    return@LaunchedEffect
                }

                else -> {
                    // unknown -> the registry entry was dropped (cancelled
                    // elsewhere?). Quietly exit.
                    activeFlow = null
                    signingIn = false
                    return@LaunchedEffect
                }
            }
        }
        // Flow expired naturally.
        if (activeFlow?.flowToken == flow.flowToken) {
            Toast
                .makeText(
                    ctx,
                    ctx.getString(R.string.drive_oauth_expired),
                    Toast.LENGTH_LONG,
                ).show()
            activeFlow = null
            signingIn = false
        }
    }

    val byoCredsReady =
        cfg.driveOauthClientId.isNotBlank() && cfg.driveOauthClientSecret.isNotBlank()

    CollapsibleSection(
        title = stringResource(R.string.sec_drive_setup),
        initiallyExpanded = true,
    ) {
        Text(
            stringResource(R.string.drive_help),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // 0. BYO OAuth credentials. rahgozar ships no embedded OAuth
        // client — every user registers their own in Google Cloud
        // Console (see docs/drive_oauth_setup.md). Comes BEFORE the
        // sign-in button so users see the prerequisite first; the
        // sign-in button is disabled until both fields are non-blank
        // AND saved (the JNI surface reads them from on-disk
        // config.json, not from this in-memory form state).
        Text(
            stringResource(R.string.drive_oauth_client_section),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            stringResource(R.string.drive_oauth_client_help),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedTextField(
            value = cfg.driveOauthClientId,
            onValueChange = { onChange(cfg.copy(driveOauthClientId = it)) },
            label = { Text(stringResource(R.string.drive_oauth_client_id_label)) },
            placeholder = { Text(stringResource(R.string.drive_oauth_client_id_placeholder)) },
            singleLine = true,
            enabled = !signingIn,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = cfg.driveOauthClientSecret,
            onValueChange = { onChange(cfg.copy(driveOauthClientSecret = it)) },
            label = { Text(stringResource(R.string.drive_oauth_client_secret_label)) },
            placeholder = { Text(stringResource(R.string.drive_oauth_client_secret_placeholder)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            enabled = !signingIn,
            modifier = Modifier.fillMaxWidth(),
        )

        // 1. OAuth sign-in row.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (cfg.driveHasRefreshToken) {
                Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = OkGreen)
                Text(stringResource(R.string.drive_signed_in), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.weight(1f))
                OutlinedButton(
                    onClick = {
                        startDriveOauthFlow(ctx, scope, { signingIn = it }, { activeFlow = it })
                    },
                    enabled = !signingIn && byoCredsReady,
                ) {
                    Text(
                        if (signingIn) {
                            stringResource(R.string.drive_signing_in)
                        } else {
                            stringResource(R.string.drive_relink_btn)
                        },
                    )
                }
            } else {
                Icon(Icons.Filled.ErrorOutline, contentDescription = null, tint = ErrRed)
                Text(stringResource(R.string.drive_signed_out), style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.weight(1f))
                Button(
                    onClick = {
                        startDriveOauthFlow(ctx, scope, { signingIn = it }, { activeFlow = it })
                    },
                    enabled = !signingIn && byoCredsReady,
                ) {
                    Text(
                        if (signingIn) {
                            stringResource(R.string.drive_signing_in)
                        } else {
                            stringResource(R.string.drive_sign_in_btn)
                        },
                    )
                }
            }
        }
        if (!byoCredsReady) {
            // Inline hint when the user hasn't saved BYO credentials yet.
            // The Sign-in button is disabled above; this tells them why.
            Text(
                stringResource(R.string.drive_oauth_save_before_signin),
                style = MaterialTheme.typography.labelSmall,
                color = ErrRed,
            )
        }

        // 2. Folder ID + Create new.
        OutlinedTextField(
            value = cfg.driveFolderId,
            onValueChange = { onChange(cfg.copy(driveFolderId = it)) },
            label = { Text(stringResource(R.string.drive_folder_id_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            supportingText = { Text(stringResource(R.string.drive_folder_id_help)) },
            trailingIcon = {
                TextButton(
                    onClick = { showCreateFolderDialog = true },
                    enabled = cfg.driveHasRefreshToken && !creatingFolder,
                ) {
                    Text(stringResource(R.string.drive_create_folder_btn))
                }
            },
        )

        // 3. Relay pubkey + inline validation.
        OutlinedTextField(
            value = cfg.driveRelayPubkey,
            onValueChange = { onChange(cfg.copy(driveRelayPubkey = it)) },
            label = { Text(stringResource(R.string.drive_relay_pubkey_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            supportingText = {
                val v = pubkeyValidation
                when {
                    v == null -> {
                        Text(stringResource(R.string.drive_relay_pubkey_help))
                    }

                    v.first -> {
                        Text(
                            stringResource(R.string.drive_relay_pubkey_valid),
                            color = OkGreen,
                        )
                    }

                    else -> {
                        Text(
                            stringResource(R.string.drive_relay_pubkey_invalid, v.second),
                            color = ErrRed,
                        )
                    }
                }
            },
        )

        // 4. Test connection.
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = {
                    scope.launch {
                        testingConnection = true
                        lastTestResult = null
                        val resp = withContext(Dispatchers.IO) { Native.driveTestConnection() }
                        try {
                            val j = JSONObject(resp)
                            if (j.optBoolean("ok", false)) {
                                val folder = j.optString("folder_id", "")
                                val count = j.optInt("files_count", 0)
                                lastTestResult =
                                    ctx.getString(R.string.drive_test_ok, folder, count)
                            } else {
                                val err = j.optString("error", "unknown error")
                                Toast
                                    .makeText(
                                        ctx,
                                        ctx.getString(R.string.drive_test_failed, err),
                                        Toast.LENGTH_LONG,
                                    ).show()
                            }
                        } catch (t: Throwable) {
                            val err = t.message ?: ctx.getString(R.string.drive_parse_error)
                            Toast
                                .makeText(
                                    ctx,
                                    ctx.getString(R.string.drive_test_failed, err),
                                    Toast.LENGTH_LONG,
                                ).show()
                        }
                        testingConnection = false
                    }
                },
                enabled = cfg.driveHasRefreshToken && cfg.driveFolderId.isNotBlank() && !testingConnection,
            ) {
                Text(
                    if (testingConnection) {
                        stringResource(R.string.drive_testing)
                    } else {
                        stringResource(R.string.drive_test_btn)
                    },
                )
            }
            lastTestResult?.let {
                Text(it, color = OkGreen, style = MaterialTheme.typography.labelSmall)
            }
        }

        // 5. Advanced (poll interval + max concurrent).
        CollapsibleSection(
            title = stringResource(R.string.drive_advanced),
            initiallyExpanded = false,
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(
                    value = cfg.drivePollIntervalMs.toString(),
                    onValueChange = { s ->
                        val v = s.toIntOrNull() ?: cfg.drivePollIntervalMs
                        onChange(cfg.copy(drivePollIntervalMs = v.coerceIn(50, 60_000)))
                    },
                    label = { Text(stringResource(R.string.drive_poll_interval_label)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
                OutlinedTextField(
                    value = cfg.driveMaxConcurrentUploads.toString(),
                    onValueChange = { s ->
                        val v = s.toIntOrNull() ?: cfg.driveMaxConcurrentUploads
                        onChange(cfg.copy(driveMaxConcurrentUploads = v.coerceIn(1, 64)))
                    },
                    label = { Text(stringResource(R.string.drive_max_concurrent_label)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }

    // Device-code OAuth dialog. Visible while `activeFlow != null`.
    // Shows the user_code + verification_url with Copy + Open
    // buttons; the polling LaunchedEffect above drives completion.
    activeFlow?.let { flow ->
        AlertDialog(
            onDismissRequest = {
                // Tap-outside / back-press cancels the flow.
                scope.launch {
                    withContext(Dispatchers.IO) {
                        Native.driveOauthCancelFlow(flow.flowToken)
                    }
                }
                activeFlow = null
                signingIn = false
            },
            title = { Text(stringResource(R.string.drive_oauth_dialog_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        stringResource(R.string.drive_oauth_dialog_help, flow.verificationUrl),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    // Big monospace user_code with a Copy button.
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            flow.userCode,
                            style = MaterialTheme.typography.headlineSmall,
                            modifier = Modifier.weight(1f),
                        )
                        OutlinedButton(onClick = {
                            val clip =
                                ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                                    as? android.content.ClipboardManager
                            clip?.setPrimaryClip(
                                android.content.ClipData.newPlainText(
                                    "rahgozar OAuth code",
                                    flow.userCode,
                                ),
                            )
                            Toast
                                .makeText(
                                    ctx,
                                    ctx.getString(R.string.drive_oauth_code_copied),
                                    Toast.LENGTH_SHORT,
                                ).show()
                        }) { Text(stringResource(R.string.drive_oauth_copy_code)) }
                    }
                    Text(
                        stringResource(R.string.drive_oauth_dialog_waiting),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    // Open the verification URL in the system browser
                    // (or any handler the user has set). Best-effort —
                    // if no browser is available, the user_code in the
                    // dialog is still usable on any other device.
                    try {
                        ctx.startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse(flow.verificationUrl))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    } catch (_: Throwable) {
                        Toast
                            .makeText(
                                ctx,
                                ctx.getString(R.string.drive_browser_open_failed, flow.verificationUrl),
                                Toast.LENGTH_LONG,
                            ).show()
                    }
                }) { Text(stringResource(R.string.drive_oauth_open_url)) }
            },
            dismissButton = {
                TextButton(onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            Native.driveOauthCancelFlow(flow.flowToken)
                        }
                    }
                    activeFlow = null
                    signingIn = false
                }) { Text(stringResource(R.string.drive_oauth_cancel)) }
            },
        )
    }

    if (showCreateFolderDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!creatingFolder) showCreateFolderDialog = false
            },
            title = { Text(stringResource(R.string.drive_create_folder_dialog_title)) },
            text = {
                OutlinedTextField(
                    value = newFolderName,
                    onValueChange = { newFolderName = it },
                    label = { Text(stringResource(R.string.drive_create_folder_name_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        scope.launch {
                            creatingFolder = true
                            val resp =
                                withContext(Dispatchers.IO) {
                                    Native.driveCreateFolder(newFolderName)
                                }
                            try {
                                val j = JSONObject(resp)
                                if (j.optBoolean("ok", false)) {
                                    val folderId = j.optString("folder_id", "")
                                    onChange(latestCfg.copy(driveFolderId = folderId))
                                    showCreateFolderDialog = false
                                } else {
                                    val err = j.optString("error", "unknown error")
                                    Toast
                                        .makeText(
                                            ctx,
                                            ctx.getString(R.string.drive_create_folder_failed, err),
                                            Toast.LENGTH_LONG,
                                        ).show()
                                }
                            } catch (t: Throwable) {
                                val err = t.message ?: ctx.getString(R.string.drive_parse_error)
                                Toast
                                    .makeText(
                                        ctx,
                                        ctx.getString(R.string.drive_create_folder_failed, err),
                                        Toast.LENGTH_LONG,
                                    ).show()
                            }
                            creatingFolder = false
                        }
                    },
                    enabled = !creatingFolder && newFolderName.isNotBlank(),
                ) {
                    Text(
                        if (creatingFolder) {
                            stringResource(R.string.drive_creating_folder)
                        } else {
                            stringResource(R.string.drive_create_folder_confirm)
                        },
                    )
                }
            },
            dismissButton = {
                TextButton(
                    onClick = { showCreateFolderDialog = false },
                    enabled = !creatingFolder,
                ) {
                    Text(stringResource(R.string.drive_create_folder_cancel))
                }
            },
        )
    }
}

/** Per-flow state for the device-code dialog. Mirror of the JSON
 *  the JNI `driveOauthDeviceCodeStart` returns.
 *
 *  `intervalSecs` is the floor Google asks us to poll at (5 s
 *  typical). The LaunchedEffect bumps it on `slow_down`.
 *  `expiresInSecs` is the device_code TTL (1800 s typical) —
 *  defines the wall-clock deadline at which the LaunchedEffect
 *  gives up and the dialog dismisses.
 */
internal data class DeviceCodeFlow(
    val flowToken: String,
    val userCode: String,
    val verificationUrl: String,
    val intervalSecs: Long,
    val expiresInSecs: Long,
)

// Kick off a device-code OAuth flow. JNI start hits `/device/code`
// and returns the user-facing code + URL; the parent composable's
// polling LaunchedEffect watches for completion via
// `driveOauthPollFlow`.
private fun startDriveOauthFlow(
    ctx: Context,
    scope: CoroutineScope,
    setSigningIn: (Boolean) -> Unit,
    setActiveFlow: (DeviceCodeFlow?) -> Unit,
) {
    setSigningIn(true)
    scope.launch {
        val resp = withContext(Dispatchers.IO) { Native.driveOauthDeviceCodeStart() }
        try {
            val j = JSONObject(resp)
            if (!j.optBoolean("ok", false)) {
                val err = j.optString("error", "unknown error")
                Toast
                    .makeText(
                        ctx,
                        ctx.getString(R.string.drive_oauth_start_failed, err),
                        Toast.LENGTH_LONG,
                    ).show()
                setSigningIn(false)
                return@launch
            }
            val flowToken = j.optString("flow_token", "")
            val userCode = j.optString("user_code", "")
            val verificationUrl = j.optString("verification_url", "")
            val intervalSecs = j.optLong("interval_secs", 5L).coerceAtLeast(1L)
            val expiresInSecs = j.optLong("expires_in_secs", 1800L).coerceAtLeast(60L)
            if (flowToken.isEmpty() || userCode.isEmpty() || verificationUrl.isEmpty()) {
                Toast
                    .makeText(
                        ctx,
                        ctx.getString(R.string.drive_oauth_start_incomplete),
                        Toast.LENGTH_LONG,
                    ).show()
                setSigningIn(false)
                return@launch
            }
            setActiveFlow(
                DeviceCodeFlow(
                    flowToken = flowToken,
                    userCode = userCode,
                    verificationUrl = verificationUrl,
                    intervalSecs = intervalSecs,
                    expiresInSecs = expiresInSecs,
                ),
            )
        } catch (t: Throwable) {
            Toast
                .makeText(
                    ctx,
                    ctx.getString(
                        R.string.drive_oauth_start_failed,
                        t.message ?: ctx.getString(R.string.drive_parse_error),
                    ),
                    Toast.LENGTH_LONG,
                ).show()
            setSigningIn(false)
        }
    }
}
