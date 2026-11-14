// Copyright (c) 2026 Colin Knapp, https://colinknapp.com
// SPDX-License-Identifier: AGPL-3.0-only
(function () {
  'use strict';
  const pageName = 'Synced app settings';
  const prefix = '```json\n';
  let busy = false;
  const status = value => { window.__logseqSelfhostSettingsSync = value; };
  function parsed(block) {
    const text = block.content ?? block.title ?? block['block/title'];
    if (typeof text !== 'string' || text.length > 300 * 1024) return null;
    try {
      const value = JSON.parse(text.startsWith(prefix) && text.endsWith('\n```') ? text.slice(prefix.length, -4) : text);
      return window.LogseqSelfhostSettingsEngine.valid(value) ? { ...value, uuid: block.uuid ?? block['block/uuid'] } : null;
    } catch (_) { return null; }
  }
  async function tick() {
    if (busy || !window.apis?.readSelfhostSettings || !window.logseq?.api?.get_current_graph) return;
    busy = true;
    try {
      const api = window.logseq.api, engine = window.LogseqSelfhostSettingsEngine;
      const graph = await api.get_current_graph();
      if (!graph?.name?.startsWith('logseq_db_')) return;
      const encrypted = await api.datascript_query('[:find ?v . :where [?e :db/ident :logseq.kv/graph-rtc-e2ee?] [?e :kv/value ?v]]');
      const remote = await api.datascript_query('[:find ?v . :where [?e :db/ident :logseq.kv/graph-remote?] [?e :kv/value ?v]]');
      if (encrypted !== true || remote !== true) { status({ state: 'waiting-for-encrypted-sync' }); return; }
      const key = 'logseq-selfhost-settings/v1:' + graph.name;
      let saved;
      try { saved = JSON.parse(localStorage.getItem(key)); } catch (_) { saved = null; }
      const writerKey = 'logseq-selfhost-settings-device/v1';
      const writer = localStorage.getItem(writerKey) || crypto.randomUUID();
      localStorage.setItem(writerKey, writer);
      const local = await window.apis.readSelfhostSettings();
      const existingPage = await api.get_page(pageName);
      const tree = existingPage ? await api.get_page_blocks_tree(pageName) || [] : [];
      const records = tree.map(parsed).filter(Boolean);
      const plan = engine.reconcile(local.files, saved, records, writer, Date.now());
      // Do not act on another graph if the user switches during an async read.
      if ((await api.get_current_graph())?.name !== graph.name) return;
      let restored = false;
      for (const r of plan.restore) {
        const result = await window.apis.restoreSelfhostSettings({ path: r.path, document: r.document });
        restored = restored || result.restored;
      }
      if (plan.publish.length && !existingPage) {
        await api.create_page(pageName, {}, { redirect: false, createFirstBlock: false });
      }
      for (const r of plan.publish) {
        if ((await api.get_current_graph())?.name !== graph.name) return;
        const content = prefix + JSON.stringify(r) + '\n```';
        const own = records.find(old => old.path === r.path && old.writer === writer && old.uuid);
        // Configuration is stored ONLY as block content: this is a native E2EE
        // attribute. Plugin properties and kv/value are deliberately unused.
        if (own) await api.update_block(own.uuid, content);
        else await api.append_block_in_page(pageName, content);
      }
      const after = await window.apis.readSelfhostSettings();
      const fingerprints = Object.fromEntries(Object.entries(after.files).map(([name, doc]) => [name, engine.fingerprint(doc)]));
      localStorage.setItem(key, JSON.stringify({ fingerprints, seen: plan.seen }));
      status({ state: 'synced', files: Object.keys(after.files).length, keptLocal: after.skipped.length, needsReload: restored });
      if (restored && typeof api.show_msg === 'function') {
        api.show_msg('Plugin list and portable settings restored. Reopen Logseq to load changes; use Install plugins from file for missing plugins.', 'success');
      }
    } catch (_) { status({ state: 'pending', message: 'Settings sync will retry. Local settings are preserved.' }); }
    finally { busy = false; }
  }
  window.addEventListener('focus', tick);
  setInterval(tick, 15000);
  tick();
})();
