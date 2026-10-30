// SPDX-License-Identifier: BSD-3-Clause

import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';

import {SECURE_SHELL, SECURE_SHELL_DEV, callerName} from '../src/callers.js';

const SETTINGS = {allowDevSecureShell: false};

test('Secure Shell is allowed and its dev channel is opt-in', () => {
  assert.equal(callerName({id: SECURE_SHELL}, SETTINGS), 'Secure Shell');
  assert.equal(callerName({id: SECURE_SHELL_DEV}, SETTINGS), null);
  assert.equal(callerName({id: SECURE_SHELL_DEV},
                         {allowDevSecureShell: true}), 'Secure Shell (dev)');
});

test('ChromeOS Terminal connects without an extension ID', () => {
  for (const url of [
    'chrome-untrusted://terminal/',
    'chrome-untrusted://terminal/html/terminal.html?command=ssh#profile',
    'chrome-untrusted://terminal/html/terminal_ssh.html',
  ]) {
    assert.equal(callerName({url}, SETTINGS), 'ChromeOS Terminal');
  }
});

test('other pages and extensions are refused', () => {
  for (const url of [
    undefined, '', 'invalid',
    'https://terminal/html/terminal.html',
    'chrome://terminal/html/terminal.html',
    'chrome-untrusted://crosh/',
    'chrome-untrusted://terminal.evil.example/',
    'chrome-untrusted://terminal@evil.example/',
    'chrome-untrusted://terminal:1234/',
    'chrome-untrusted://terminal',
  ]) {
    assert.equal(callerName({url}, SETTINGS), null, url);
  }
  assert.equal(callerName(undefined, SETTINGS), null);
  for (const id of ['other-extension', SECURE_SHELL_DEV]) {
    assert.equal(callerName({id, url: 'chrome-untrusted://terminal/'},
                           SETTINGS), null);
  }
});

test('the manifest allows only the supported clients', () => {
  const manifest = JSON.parse(readFileSync(
      new URL('../manifest.json', import.meta.url), 'utf8'));
  assert.deepEqual(manifest.externally_connectable, {
    ids: [SECURE_SHELL, SECURE_SHELL_DEV],
    matches: ['chrome-untrusted://terminal/*'],
  });
});
