# Privacy policy

WebAuthn SSH Agent does not collect, transmit or sell any data.

**What it stores.**  For each SSH key you create or import: the key's name,
its public key, its WebAuthn credential ID, the extension's RP ID, the creation
date, the key's settings and place in the list, what its authenticator
reported about it (e.g. its model ID and whether it can sync), and any
OpenSSH certificate you add to it (which names the users it's for).  This
is stored with `chrome.storage.sync`, i.e. in your Chrome profile, which
Chrome syncs between your own devices if you have sync turned on.  None of it is secret:
only your security key or passkey provider can use the private keys, and a
credential ID is useless without it.

On this computer only (`chrome.storage.local`, not synced): the extension's
settings, and a hash of each key verified on this computer.

**What it shares.**  Nothing.  The extension makes no network requests.  It
only answers SSH agent requests from Secure Shell or the ChromeOS Terminal
app.  The client sends the signatures to the SSH servers you connect to, as
with any SSH key.

**What it can access.**  Only its own storage.  It has no access to websites,
your browsing, or other extensions' data.

**Removing data.**  Forget keys in the extension's **Manage keys and
settings** page, or remove the extension.  Keys stored on a security key are
removed with the key's own tools (e.g. `ykman fido credentials delete`), and
passkeys in their provider.
