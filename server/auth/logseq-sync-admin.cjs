#!/usr/bin/env node
'use strict';
// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
const grants = require('./grants.cjs');
const code = require('./code-identity.cjs');
function main(args) {
  const [command, ...values] = args;
  if (command === 'grant' && values.length === 1) {
    const identity = code.createIdentity();
    const grant = grants.addGrant(identity.subject, values[0]);
    // The operator must treat stdout as a secret. No wrapping root is persisted.
    process.stdout.write(JSON.stringify({...grant, syncCode: code.encodeCode(identity)}) + '\n');
    return;
  }
  if (command === 'list' && values.length === 0) {
    process.stdout.write(JSON.stringify(grants.readRegistry(undefined, {allowMissing: true}).grants, null, 2) + '\n');
    return;
  }
  if (command === 'revoke' && values.length === 1) {
    process.stdout.write(JSON.stringify(grants.revokeGrant(values[0])) + '\n');
    return;
  }
  if (command === 'import' && (values.length === 2 || values.length === 3 && values[2] === '--legacy')) {
    const [subject, label] = values, legacy = values[2] === '--legacy';
    if (legacy && subject !== process.env.LOGSEQ_OWNER_USER_ID) throw Error('Legacy grant must match configured legacy owner');
    if (!legacy && subject === process.env.LOGSEQ_OWNER_USER_ID) throw Error('Configured legacy owner requires --legacy');
    process.stdout.write(JSON.stringify(grants.addGrant(subject, label, legacy ? 'legacy-hs256' : 'ed25519')) + '\n');
    return;
  }
  throw Error('Usage: logseq-sync-admin grant <label> | list | revoke <id> | import <subject> <label> [--legacy]');
}
if (require.main === module) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    // Do not echo argv, filesystem contents, or generated credentials on errors.
    const allowed = /^(Usage:|Invalid grant|Grant not found|Identity already|Legacy grant|Configured legacy|Grant registry)/;
    process.stderr.write((allowed.test(error.message) ? error.message : 'Grant operation failed; inspect local registry permissions and lock') + '\n');
    process.exitCode = 1;
  }
}
module.exports = {main};
