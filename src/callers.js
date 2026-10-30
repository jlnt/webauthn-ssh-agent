// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview The clients allowed to use this agent.
 *
 * Keep in sync with "externally_connectable" in manifest.json, which makes
 * Chrome refuse connections from other extensions and web pages before they
 * reach us.
 *
 * IDs from Secure Shell's own list in libapps' nassh_external_api.js.
 *
 * Note: an extension ID is derived from a public key, so someone who can load
 * unpacked extensions on this computer could make one with Secure Shell's ID.
 * The allowlist protects against extensions installed from the Web Store,
 * not against local developer access.
 */

/** Secure Shell from the Chrome Web Store. */
export const SECURE_SHELL = 'iodihamcpbpeioajjeobimgagajmlibd';

/** Secure Shell's dev channel: only with the allowDevSecureShell setting. */
export const SECURE_SHELL_DEV = 'algkcnfjnajfhgimadimbjhmpaeohhln';

/**
 * @param {{id?: string, url?: string}|undefined} sender The caller from Chrome.
 * @param {{allowDevSecureShell: boolean}} settings
 * @return {?string} The name to show the user, or null if not allowed.
 */
export function callerName(sender, settings) {
  if (sender?.id === SECURE_SHELL) {
    return 'Secure Shell';
  }
  if (sender?.id === SECURE_SHELL_DEV && settings.allowDevSecureShell) {
    return 'Secure Shell (dev)';
  }
  // Terminal is a system web app, so Chrome supplies a URL without an ID.
  if (!sender?.id &&
      sender?.url?.startsWith('chrome-untrusted://terminal/')) {
    return 'ChromeOS Terminal';
  }
  return null;
}
