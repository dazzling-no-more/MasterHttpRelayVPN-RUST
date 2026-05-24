# Drive Mode — OAuth client setup (BYO)

Drive Mode talks to Google Drive on your behalf. Google requires this kind of
access to come with an **OAuth client** that you (the user) register in
your own Google Cloud Console.

rahgozar ships **no embedded OAuth client**. Every user creates their own
and pastes the two resulting values — `client_id` and `client_secret` —
into the Drive setup screen or relay CLI.

This is a one-time, ~10-minute task. Once done, Drive Mode works
forever for you and the people you share that OAuth client with (up to
100 users, see [Why BYO?](#why-byo) below).

> 🇮🇷 Persian version: [drive_oauth_setup.fa.md](drive_oauth_setup.fa.md)

---

## Step 0 — What you need

- A Google account. The same one whose Drive will hold the encrypted
  mailbox folder is the most convenient.
- A web browser with the Google account signed in.
- Five to ten minutes.

You do **not** need:

- A paid Google Cloud account. Everything below is free-tier.
- A domain or homepage. Drive Mode's OAuth scope is
  `drive.file` — Google's review process does not require a privacy
  policy URL until you go through full verification (which most users
  never need).
- Any code changes. The credentials are pasted into rahgozar's setup
  screen at runtime.

---

## Step 1 — Create a Google Cloud project

1. Open <https://console.cloud.google.com/>.
2. Top bar: click the project picker (it shows your current project
   or "Select a project").
3. Click **New project** in the dialog.
4. Project name: anything you like (e.g. `rahgozar-drive`).
   Organization / location: leave as default.
5. Click **Create** and wait for the project to be ready (~10
   seconds). The picker should switch to the new project
   automatically; if not, pick it manually.

---

## Step 2 — Enable the Drive API

1. With your new project selected, open
   <https://console.cloud.google.com/apis/library/drive.googleapis.com>.
2. Click **Enable**.
3. Wait for the "API enabled" confirmation. There's nothing else to
   click here.

---

## Step 3 — Configure the OAuth consent screen

This is the page users will see when they first sign in.

1. Open <https://console.cloud.google.com/auth/branding>.
2. Pick **External** (Internal is for Google Workspace
   organisations).
3. Fill the required fields:
   - **App name**: anything (e.g. `rahgozar-drive` or your initials —
     it's shown to YOU during sign-in, so it just has to be
     recognisable).
   - **User support email**: your Gmail address.
   - **Developer contact information**: your Gmail address.
4. Save and continue. Skip the "Scopes" step — `drive.file` is a
   non-sensitive scope that's added automatically when you create the
   client in step 4.
5. On the "Test users" step, **add your own Gmail address** as a test
   user. Without this, your own sign-in will be blocked with
   "Access blocked — this app is being tested." If you'll let other
   people use this client too, add their emails here as well
   (up to 100 total).
6. Save and continue, then **Back to dashboard**.
7. The dashboard will say **Publishing status: Testing**. This is
   fine. See [Why BYO?](#why-byo) for what Testing vs Production
   means.

---

## Step 4 — Create the OAuth client

1. Open <https://console.cloud.google.com/apis/credentials>.
2. Top bar: **+ Create credentials** → **OAuth client ID**.
3. **Application type**:
   - Desktop app: choose **Desktop app**.
   - Android app or VPS relay device-code flow: choose
     **TVs and Limited Input devices**.
4. Name: anything clear (e.g. `rahgozar-desktop` or
   `rahgozar-device-code`).
5. Click **Create**.
6. A dialog pops up with two values. **Copy both.** These are what
   you'll paste into the matching rahgozar surface:
   - **Client ID** — ends in `.apps.googleusercontent.com`
   - **Client secret** — starts with `GOCSPX-`

   You can re-open these from the Credentials list at any time, so
   don't worry if the dialog closes. The download-JSON button is
   optional; the two strings are all rahgozar needs.

---

## Step 5 — Paste into rahgozar

### Desktop (Tauri UI)

1. Open rahgozar, switch the mode picker to **Drive**.
2. Scroll to the Drive setup section.
3. At the top, paste the **Desktop app** OAuth client:
   - **Client ID** — the `…apps.googleusercontent.com` value.
   - **Client secret** — the `GOCSPX-…` value.
4. **Save** the config. Until you save, "Sign in with Google" stays
   disabled.
5. Now click **Sign in with Google**. The browser opens, you pick
   your account, click "Continue" past the "Google hasn't verified
   this app" warning if Google shows one (see [Why BYO?](#why-byo)),
   and rahgozar shows "Signed in."

### Android

1. Same Drive setup screen, same two fields at the top. Paste the
   **TVs and Limited Input devices** OAuth client — not the Desktop
   app client.
2. Save the config (the toolbar Save button).
3. Tap **Sign in with Google**. rahgozar shows a device code and a
   Google verification URL.
4. Open the URL in the browser, enter the code, and approve access.
   rahgozar polls in the background and then shows "Signed in."

### VPS relay (`rahgozar-drive-relay`)

The relay also uses the device-code flow, so pass the **TVs and
Limited Input devices** client:

```bash
rahgozar-drive-relay oauth device-code \
  --client-id     "<your client_id>" \
  --client-secret "<your client_secret>" \
  --out /etc/rahgozar-drive-relay/config.json
```

Or set environment variables before running:

```bash
export RAHGOZAR_OAUTH_CLIENT_ID="<your client_id>"
export RAHGOZAR_OAUTH_CLIENT_SECRET="<your client_secret>"
rahgozar-drive-relay oauth device-code --out /etc/rahgozar-drive-relay/config.json
```

The relay then prints a `user_code` and a URL. Open the URL in any
browser, enter the code, and the relay's `config.json` is updated
with all three values (`oauth_client_id` + `oauth_client_secret` +
`oauth_refresh_token`).

Use clients from the same Google Cloud project and consent screen so
they share the same test-user list, Drive API enablement, and
`drive.file` app identity. Do **not** create the desktop client in one
project and the Android/relay client in another: `drive.file` access is
scoped to the app/project that created or opened the files, so splitting
projects can make the relay and client unable to see each other's
mailbox files even when they use the same Google account and folder ID.

---

## Why BYO?

Google caps OAuth clients in **Testing** mode at **100 manually-added
test users**. Apps published to **Production** without going through
verification show a yellow "Google hasn't verified this app" warning
and are capped at **100 lifetime authorizations** on sensitive scopes
like `drive.file`.

Full verification removes both, but it's a multi-week review process
that Google has been tightening for proxy/tunnel-shaped apps.

If rahgozar shipped one shared OAuth client, that client would hit
100 users very quickly and stop working for everyone. BYO sidesteps
this entirely: every user has their own quota of 100 they'll likely
never hit.

The "client secret" Google gives you is **not actually secret** for
installed apps — RFC 8252 §8.6 acknowledges this. Treat the client_id
+ client_secret pair the same way you'd treat a personal Drive folder
ID: not public, but not catastrophic to leak either. The pair only
grants the holder access to **files this specific OAuth client
created in your Drive** (the `drive.file` scope) — not your whole
Drive, not your email, not your photos.

---

## Common issues

**"Access blocked — this app is being tested"** during sign-in.

You missed Step 3.5 — adding your own Gmail as a test user. Open
<https://console.cloud.google.com/auth/audience>, scroll to "Test
users", click **+ Add users**, paste the email shown on the blocked
page, save. Re-try sign-in.

**"Google hasn't verified this app"** warning during sign-in.

Expected for an unverified client in Production status, OR if your
client is published to Production from the consent-screen settings.
Click **Advanced → Go to <app name> (unsafe)**. The warning will
keep appearing every sign-in — that's normal for an unverified app
and doesn't affect functionality.

**`invalid_client` error after sign-in attempt.**

The client_id or client_secret pasted into rahgozar doesn't match
what's in Google Cloud Console. Double-check you copied both fully
(client secrets are long), and that there's no whitespace at the
start or end. Also check the client type: desktop sign-in needs a
**Desktop app** client, while Android and `rahgozar-drive-relay oauth
device-code` need a **TVs and Limited Input devices** client. Save the
rahgozar config and try again.

**`access_denied` error.**

You clicked "Cancel" or closed the browser window during sign-in.
Just click "Sign in with Google" again.

**"This app is blocked" — `disallowed_useragent`**.

Happens on some embedded WebViews. rahgozar uses your system
browser, not a WebView, so you shouldn't see this. If you do, file
a bug.

---

## Rotating credentials

If you ever leak your `client_secret` (e.g. pasted it in a public
screenshot), open
<https://console.cloud.google.com/apis/credentials>, click your
client, **Reset secret**, paste the new secret into rahgozar's setup
screen, save, and re-link Drive (Sign in again — the refresh token
issued under the old secret will keep working until you revoke it,
but rotating both halves is cleanest).

You can also delete the client entirely from the Credentials page if
you want to stop using Drive Mode and free up the 100-user slot.
