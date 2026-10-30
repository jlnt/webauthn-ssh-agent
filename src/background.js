// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Service worker: serves the SSH agent protocol to SSH clients
 * (`--ssh-agent=<this extension's id>`) and opens a small window to have the
 * user confirm each signature with their security key or passkey, since
 * service workers can't use WebAuthn.
 */

import {handleRequest} from './agent.js';
import {SessionBindings} from './binding.js';
import {callerName} from './callers.js';
import {
  WEBAUTHN_TIMEOUT_MS, confirmationFor, keyBlob, keyCertificate, loadKeys,
} from './keys.js';
import {Decision, assess} from './policy.js';
import {loadSettings} from './settings.js';
import {isCertificateCurrent} from './ssh.js';
import {displayText} from './text.js';

/** Limit on the size of an agent request; real ones are a few KiB at most. */
const MAX_REQUEST_BYTES = 256 * 1024;

/** How long the touch window shows "Done." after signing. */
const SUCCESS_DISPLAY_MS = 800;

/**
 * Signature requests one connection may have waiting; more are refused, so a
 * client can't flood the user with prompts.
 */
const MAX_PENDING_PER_CONNECTION = 2;

/** The message type Secure Shell's agent relay uses. */
const AGENT_MESSAGE_TYPE = 'auth-agent@openssh.com';

/** How long to wait for the details window to show the request. */
const DETAILS_TIMEOUT_MS = 3000;

/**
 * Signature requests waiting for the user, by random ID.
 *
 * @type {!Map<string, {
 *   key: !Object,
 *   certificate: (string|undefined),
 *   data: !Uint8Array,
 *   caller: string,
 *   decision: string,
 *   fields: !Object,
 *   connection: !Connection,
 *   windowId: (number|undefined),
 *   detailsWindowId: (number|undefined),
 *   detailsShown: (function()|undefined),
 *   resolve: function(!Uint8Array),
 *   reject: function(!Error),
 * }>}
 */
const pending = new Map();

/**
 * State of one agent connection (one Secure Shell agent socket).
 *
 * @typedef {{
 *   caller: string,
 *   bindings: !SessionBindings,
 *   pending: number,
 *   denied: boolean,
 * }}
 */
let Connection;

/** Serializes signature requests: one touch window at a time. */
let signQueue = Promise.resolve();

/** Whether we already opened "Manage keys and settings" as no keys exist. */
let openedManagePage = false;

/**
 * Ask the user to sign in a window.
 *
 * @param {{key: !Object, certificate: (string|undefined)}} identity The
 *     StoredKey to use, & the key ID of its certificate if that's what's
 *     offered.
 * @param {!Uint8Array} data The SSH data to sign.
 * @param {!Connection} connection Where the request came from.
 * @param {string} decision A policy Decision other than refuse.
 * @param {!Object} fields What to show the user (policy Fields).
 * @return {!Promise<!Uint8Array>} The SSH signature.
 */
function signInWindow({key, certificate}, data, connection, decision,
                      fields) {
  if (connection.pending >= MAX_PENDING_PER_CONNECTION) {
    return Promise.reject(new Error('too many pending requests'));
  }
  ++connection.pending;
  const run = () => new Promise((resolve, reject) => {
    if (connection.denied) {
      reject(new Error('denied for this connection'));
      return;
    }
    const id = crypto.randomUUID();
    const request = {id, key, certificate, data, caller: connection.caller,
                     decision, fields, connection, resolve, reject};
    pending.set(id, request);
    /** @param {number} delay How long to leave the window up. */
    const finish = (delay) => {
      clearTimeout(timer);
      pending.delete(id);
      for (const windowId of [request.windowId, request.detailsWindowId]) {
        if (windowId !== undefined) {
          setTimeout(
              () => chrome.windows.remove(windowId).catch(() => {}), delay);
        }
      }
    };
    request.resolve = (signature) => {
      // Leave "Done." up briefly so the user sees it worked.
      finish(SUCCESS_DISPLAY_MS);
      resolve(signature);
    };
    request.reject = (error) => {
      finish(0);
      reject(error);
    };
    const timer = setTimeout(
        () => request.reject(new Error('timed out')),
        WEBAUTHN_TIMEOUT_MS + 30 * 1000);
    chrome.windows.create({
      url: chrome.runtime.getURL(`src/sign.html#${id}`),
      type: 'popup',
      width: 640,
      height: 560,
      focused: true,
    }).then((win) => {
      if (pending.has(id)) {
        request.windowId = win.id;
      } else {
        chrome.windows.remove(win.id).catch(() => {});
      }
    }, request.reject);
  });
  const result = signQueue.then(run, run)
      .finally(() => --connection.pending);
  signQueue = result.catch(() => {});
  return result;
}

// Closing a touch window cancels its request: the window keeps a port open,
// which closes with it.  (Unlike chrome.windows.onRemoved, this doesn't wake
// the service worker whenever any window closes.)
chrome.runtime.onConnect.addListener((port) => {
  const url = port.sender?.url ?? '';
  if (port.sender?.id !== chrome.runtime.id ||
      !url.startsWith(chrome.runtime.getURL('src/sign.html'))) {
    return;
  }
  const id = new URL(url).hash.slice(1);
  port.onDisconnect.addListener(
      () => pending.get(id)?.reject(new Error('cancelled')));
});

/**
 * Open the details window, beside the touch window, wait until it shows the
 * request, and give the focus back to the touch window (WebAuthn needs it).
 *
 * @param {!Object} request
 * @param {*} bounds Where the touch window asked for it.
 * @return {!Promise<void>}
 */
async function showDetails(request, bounds) {
  if (request.detailsWindowId !== undefined) {
    return;
  }
  const shown = new Promise((resolve) => {
    request.detailsShown = resolve;
    setTimeout(resolve, DETAILS_TIMEOUT_MS);
  });
  const valid = (n, min, max) => Number.isInteger(n) && n >= min && n <= max;
  const {left, top, width, height} = bounds ?? {};
  const win = await chrome.windows.create({
    url: chrome.runtime.getURL(`src/details.html#${request.id}`),
    type: 'popup',
    focused: false,
    ...(valid(left, -1e5, 1e5) && valid(top, -1e5, 1e5) ? {left, top} : {}),
    width: valid(width, 200, 2000) ? width : 440,
    height: valid(height, 200, 2000) ? height : 560,
  });
  if (!pending.has(request.id)) {
    chrome.windows.remove(win.id).catch(() => {});
    return;
  }
  request.detailsWindowId = win.id;
  await shown;
  if (request.windowId !== undefined) {
    await chrome.windows.update(request.windowId, {focused: true});
  }
}

// Messages from our touch & details windows.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    return;
  }
  const request = pending.get(msg?.id);
  // The details window only gets what it shows.
  if (sender.url?.startsWith(chrome.runtime.getURL('src/details.html'))) {
    if (msg.type === 'details-shown') {
      request?.detailsShown?.();
      sendResponse(null);
      return;
    }
    sendResponse(msg.type === 'get-request-details' && request ? {
      caller: request.caller,
      fields: request.fields,
      key: {comment: request.key.comment},
      certificate: request.certificate,
    } : null);
    return;
  }
  if (!sender.url?.startsWith(chrome.runtime.getURL('src/sign.html'))) {
    return;
  }
  if (!request) {
    sendResponse(null);
    return;
  }
  switch (msg.type) {
    case 'show-details':
      showDetails(request, msg.bounds).catch(
          (e) => console.warn('no details window:', e))
          .finally(() => sendResponse(null));
      return true;  // Responds asynchronously.
    case 'get-sign-request':
      sendResponse({
        key: request.key,
        certificate: request.certificate,
        data: Array.from(request.data),
        caller: request.caller,
        decision: request.decision,
        fields: request.fields,
      });
      break;
    case 'deny-connection':
      // Refuse this & everything else from the same connection.
      request.connection.denied = true;
      request.reject(new Error('denied for this connection'));
      sendResponse(null);
      break;
    case 'sign-result':
      if (Array.isArray(msg.signature)) {
        request.resolve(Uint8Array.from(msg.signature));
      } else {
        request.reject(new Error(String(msg.error)));
      }
      sendResponse(null);
      break;
  }
});

/**
 * @param {*} msg
 * @return {?Uint8Array} The agent request, if msg is well formed.
 */
function parseAgentMessage(msg) {
  if (msg?.type !== AGENT_MESSAGE_TYPE || !Array.isArray(msg.data) ||
      msg.data.length === 0 || msg.data.length > MAX_REQUEST_BYTES ||
      !msg.data.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)) {
    return null;
  }
  return Uint8Array.from(msg.data);
}

// SSH clients connect here when --ssh-agent=<our id> is set; each agent
// socket is a separate connection.  Check the caller again, as the Secure
// Shell dev channel is opt-in.
chrome.runtime.onConnectExternal.addListener((port) => {
  // Hold messages until we know whether to serve this connection.
  const early = [];
  const hold = (msg) => early.push(msg);
  port.onMessage.addListener(hold);
  loadSettings().then((settings) => {
    port.onMessage.removeListener(hold);
    const caller = callerName(port.sender, settings);
    if (!caller) {
      console.warn('rejected connection from', port.sender);
      port.disconnect();
      return;
    }
    serve(port, caller, early);
  }).catch((e) => {
    console.warn('rejected connection:', e);
    port.disconnect();
  });
});

/**
 * What the agent offers for a key: the key, after its certificate if it has
 * a valid one.  ssh asks the server which it accepts before asking for a
 * signature, so offering both costs no touch.
 *
 * @param {!Object} key A StoredKey.
 * @return {!Array<{key: !Object, blob: !Uint8Array, comment: string,
 *                  certificate: (string|undefined)}>} Agent Identities, with
 *     the key, & the certificate's key ID (for the user) if it's one.
 */
function identitiesOf(key) {
  const plain = {key, blob: keyBlob(key), comment: key.comment};
  const cert = keyCertificate(key);
  if (!cert || !isCertificateCurrent(cert)) {
    return [plain];
  }
  return [{key, blob: cert.blob, comment: key.comment,
           certificate: displayText(cert.keyId)}, plain];
}

/**
 * Serve the agent protocol on a connection.
 *
 * @param {!chrome.runtime.Port} port
 * @param {string} caller The client's name, for the user.
 * @param {!Array<*>} early Messages that arrived before we were ready.
 */
function serve(port, caller, early) {
  /** @type {!Connection} */
  const connection = {
    caller,
    bindings: new SessionBindings(),
    pending: 0,
    denied: false,
  };

  const identities = async () => {
    const keys = await loadKeys();
    if (keys.length === 0 && !openedManagePage) {
      // Help first-time users find where keys are created.
      openedManagePage = true;
      chrome.runtime.openOptionsPage();
    }
    return keys.flatMap(identitiesOf);
  };
  const backend = {
    identities,
    sign: async (identity, data) => {
      // Settings may have changed since the connection started (e.g. in a
      // touch window).
      const settings = await loadSettings();
      const confirmation = await confirmationFor(identity.key, settings);
      const {decision, reason, fields} = await assess(
          data, connection.bindings, {...settings, confirmation});
      if (decision === Decision.REFUSE) {
        throw new Error(`refused: ${reason}`);
      }
      return signInWindow(identity, data, connection, decision, fields);
    },
    bind: (hostKey, sessionId, signature, forwarded) =>
      connection.bindings.bind(hostKey, sessionId, signature, forwarded),
  };

  // Handle requests in order: the protocol has no request IDs.
  let queue = Promise.resolve();
  const onMessage = (msg) => {
    queue = queue.then(async () => {
      const request = parseAgentMessage(msg);
      if (request === null) {
        port.disconnect();
        return;
      }
      const response = await handleRequest(request, backend);
      try {
        port.postMessage(
            {type: AGENT_MESSAGE_TYPE, data: Array.from(response)});
      } catch (e) {
        // The client went away.
      }
    });
  };
  port.onMessage.addListener(onMessage);
  early.forEach(onMessage);
}

// The toolbar button opens "Manage keys and settings".
chrome.action.onClicked.addListener(() => chrome.runtime.openOptionsPage());
