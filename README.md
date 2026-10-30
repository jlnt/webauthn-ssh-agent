# WebAuthn SSH Agent

An SSH agent for Chrome's [Secure Shell] and the ChromeOS Terminal app,
with SSH keys bound to a **security key** (YubiKey, Titan, …) or a **passkey**,
via WebAuthn.  The extension never has access to a private key, and every
login needs your security key or passkey.

Works with the regular Secure Shell; no native helpers.  Servers need OpenSSH
8.4+.

## Install

Install it from the [Chrome Web Store].

To try a development build, download the zip from the [releases page], unzip
it, and in `chrome://extensions` enable **Developer mode** and **Load
unpacked** the folder.

## Use

1. Click the extension's toolbar button to open **Manage keys and settings**,
   create a key, and add its public key to `~/.ssh/authorized_keys` on your
   servers.
2. In Secure Shell or the ChromeOS Terminal app's SSH connection settings,
   set **SSH relay server options** to the `--ssh-agent=…` line shown in
   **Manage keys and settings**.
3. Connect, check the request that pops up, click **Continue** (or press
   Enter), and confirm with your security key or passkey.

For direct logins to a verified server, the **Confirmation** level, set per
key (synced with it) or as a default, sets how much you see: **Review** (the
default) shows the request and waits for Continue, **Show** opens the security
key or passkey prompt right away with the request beside it, and **Silent**
only shows that prompt.  A key's own
level applies once it's verified on this computer.  Other requests are always
reviewed.

Keys are offered to servers in the key list's order: drag a row by its handle
to change it.

If your servers trust an OpenSSH CA (`TrustedUserCAKeys`), have it sign a
key's public key and add the certificate with the key's **+** button.  While
valid, the certificate is offered before the key.  For a key that requires a
PIN or fingerprint, ask the CA for `-O verify-required`.

Agent forwarding (`ssh -A`) works, with an extra confirmation per login.  On
the server you forward the agent to, `ssh` must be OpenSSH 10.3+: older
versions reject the WebAuthn signatures a browser makes when they come from an
agent.

## Supported authenticators

Everything goes through WebAuthn, so any authenticator Chrome supports works:

| Authenticator | What you get |
|---|---|
| **U2F-only security key** (older keys) | Non-discoverable keys, and a touch to log in: U2F has no discoverable keys and no PIN or fingerprint. |
| **FIDO2 security key** (YubiKey 5, Titan, SoloKey, Nitrokey, …) | Everything: optional discoverable keys, and a PIN or fingerprint for every login, enforced by the security key itself. |
| **Passkey** (Google Password Manager, iCloud Keychain, Windows Hello, a phone, …) | Always discoverable, usually synced, unlocked with your screen lock or biometrics. |

Keys are ECDSA P-256 only: OpenSSH's WebAuthn signature format doesn't exist
for Ed25519.  Keys made with `ssh-keygen -t ecdsa-sk` can't be used (they're
bound to `ssh:`, which browsers don't allow); create keys here instead, and one
security key can hold both.

## Where keys live

*Security key* and *passkey* are everyday names; the key list uses WebAuthn's
terms.  Here, a security key is a cross-platform authenticator whose
credentials are single-device: bound to it, so only it can use the private
key.  A passkey is a discoverable credential on a platform authenticator or
phone, usually multi-device: it can sync.

| | Security key | Security key, stored on the key | Passkey |
|---|---|---|---|
| **Private key** | Stored encrypted in your Chrome profile (synced); only that specific security key can decrypt and use it | Stored in one of the security key's slots (a *discoverable credential*, or *resident key*) | Held by the platform authenticator or phone (may sync) |
| **Login needs** | The security key + the synced credential ID | The security key | The platform authenticator or phone |
| **How to use on a new computer** | Appears through Chrome sync; plug in the security key | Appears through Chrome sync, or **Import** with the security key | Appears through Chrome sync, or **Import**; the passkey must be available there (synced, or on your phone) |
| **Key list shows** | Cross-platform, Single-device | Cross-platform, Discoverable, Single-device | Platform (Cross-platform for a phone), Discoverable, usually backed up (✓) |

**Add a key** asks Chrome for one of these, but its prompt can offer
something else: the key list shows what you got, in red if you wanted a
security key and got a multi-device key.

The extension stores only public data (public key, credential ID, name),
synced with your Chrome profile.  For a key not stored on the security key,
the credential ID is the encrypted private key: neither it nor the security
key works without the other.

**Require a PIN or fingerprint** (*user verification*, UV in the key list)
adds `verify-required` to the `authorized_keys` line, and asks the
authenticator to enforce it too (`credProtect`).  A grey ✓ means it didn't
confirm, so only servers enforce it.

## Security

* Only Secure Shell and the ChromeOS Terminal app can use the agent (Secure
  Shell's dev build only if you allow it in **Manage keys and settings**).
* The agent checks OpenSSH's session binding (`session-bind@openssh.com`): it
  shows the server's verified host key and refuses logins for any other
  session.
* Logins through a forwarded agent or from clients that don't bind sessions,
  and file signatures (e.g. git commits), come with a warning.  Anything else
  is refused unless you allow it.
* Keys sync through your Google account, so whoever controls it could swap
  in their own public key for you to add to your servers.  A synced key
  needs a one-time **Verify** on each computer (or turn on **Trust keys
  synced**); until then its own confirmation level is ignored.
* Only the `storage` permission, a strict content security policy, no
  dependencies.

## How it works

Secure Shell relays agent requests to this extension, which offers
`sk-ecdsa-sha2-nistp256@openssh.com` keys and signs with
`navigator.credentials.get()`, in OpenSSH's
`webauthn-sk-ecdsa-sha2-nistp256@openssh.com` format (see [PROTOCOL.u2f]).
Keys are bound to the extension's origin.

## Development

```
node --test 'test/*.test.js'   # unit tests
./test/e2e/run.sh              # end to end; needs sshd, jq & Playwright
scripts/package.sh out.zip     # --store: Chrome Web Store build
node scripts/store-assets.mjs  # store images
node scripts/aaguids.mjs       # refresh authenticator model names
```

To release, change the version in `manifest.json` and push to `main`: CI
publishes the release, tagged `v<version>`, with both zips.  Other builds of
`main` are versioned `<last version>.<CI run number>`.

[Secure Shell]: https://chromewebstore.google.com/detail/iodihamcpbpeioajjeobimgagajmlibd
[Chrome Web Store]: https://chromewebstore.google.com/detail/webauthn-ssh-agent/nkcmhjokohmhogfaanphnnfdjfplkklk
[releases page]: https://github.com/jlnt/webauthn-ssh-agent/releases
[PROTOCOL.u2f]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.u2f
