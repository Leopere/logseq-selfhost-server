// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
(function (root) {
  'use strict';
  const schema = 'logseq-selfhost-settings/v1';
  const fingerprint = value => value === undefined ? null : JSON.stringify(value);
  const identity = r => `${r.clock}:${r.writer}`;
  function permitted(name) {
    return ['config/plugins.edn', 'config/config.edn', 'preferences.json'].includes(name) ||
      /^settings\/[a-z0-9][a-z0-9._-]{0,95}\.json$/i.test(name) && !name.endsWith('_layouts.json');
  }
  function valid(r) {
    return r && r.schema === schema && typeof r.path === 'string' && permitted(r.path) &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(r.writer) && Number.isSafeInteger(r.clock) && r.clock > 0 && r.clock < Date.now() + 86400000 &&
      typeof r.deleted === 'boolean' && (r.deleted || r.document && ['json', 'edn'].includes(r.document.kind));
  }
  function reconcile(local, previous, records, writer, now) {
    const baseline = previous && previous.fingerprints && previous.seen ? previous : { fingerprints: {}, seen: {} };
    const winners = Object.create(null);
    let clock = now;
    for (const r of records.filter(valid)) {
      clock = Math.max(clock, r.clock + 1);
      const old = winners[r.path];
      if (!old || r.clock > old.clock || r.clock === old.clock && r.writer > old.writer) winners[r.path] = r;
    }
    const publish = [], restore = [], seen = { ...baseline.seen };
    for (const name of new Set([...Object.keys(local), ...Object.keys(baseline.fingerprints), ...Object.keys(winners)])) {
      const remote = winners[name];
      const current = fingerprint(local[name]);
      const known = Object.hasOwn(baseline.fingerprints, name);
      const changed = known && current !== baseline.fingerprints[name];
      if (changed || !remote && local[name] !== undefined) {
        const r = { schema, path: name, writer, clock: ++clock, deleted: local[name] === undefined };
        if (!r.deleted) r.document = local[name];
        publish.push(r);
        seen[name] = identity(r);
      } else if (remote && baseline.seen[name] !== identity(remote)) {
        // Empty/new devices adopt the remote snapshot; they never publish an empty replacement.
        if (!remote.deleted && current !== fingerprint(remote.document)) restore.push(remote);
        seen[name] = identity(remote);
      }
    }
    return { publish, restore, seen };
  }
  const api = { schema, valid, identity, fingerprint, reconcile, permitted };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.LogseqSelfhostSettingsEngine = api;
})(typeof globalThis === 'undefined' ? this : globalThis);
