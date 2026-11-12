#!/usr/bin/env python3
"""Apply the reviewed operator authorization changes to pinned Logseq sources.

Copyright (c) 2026 Colin Knapp, https://colinknapp.com
SPDX-License-Identifier: AGPL-3.0-only
"""
import hashlib
from pathlib import Path
import sys

PINNED_FILES = {
    'worker/auth.cljs': '6cb32b7f0496ce3d4b1c45263893858dc9b6ff7d80f2a38ef62fe5d718f30cfa',
    'node/dispatch.cljs': '76096d9dd0eb784a4edb51230dfbefc19472c79106ee0e1f5cd08529fb4a469d',
    'node/server.cljs': '0e0874dace7fe1b5316da31fa9dc0e2ec40c66adb93415a392682eb138076259',
}
HEADER = '; Modified 2026-11-12 for explicit operator authorization\n; Operator authorization changes Copyright (c) 2026 Colin Knapp, https://colinknapp.com\n; SPDX-License-Identifier: AGPL-3.0-only\n'


def replace_region(text, start, end, replacement):
    if text.count(start) != 1 or (end and text.count(end) != 1):
        raise RuntimeError('Reviewed source boundary changed')
    first = text.index(start)
    last = text.index(end, first) if end else len(text)
    return text[:first] + replacement + text[last:]


def patch(root):
    directory = root / 'deps/db-sync/src/logseq/db_sync'
    sources = {}
    # Validate every input before changing any file.
    for relative, digest in PINNED_FILES.items():
        raw = (directory / relative).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Unreviewed upstream source: ' + relative)
        sources[relative] = raw.decode('utf8')

    auth = sources['worker/auth.cljs']
    auth = replace_region(auth, '(defn auth-claims [request env]', '(defn personal-access-token?', '''(defn auth-claims [request _env]
  ((aget (js/require "/app/auth/owner-auth.cjs") "verifyRequest") request))

''')
    auth = replace_region(auth, '(defn semantic-auth-claims', None, '''(defn semantic-auth-claims [request env]
  (auth-claims request env))
''')
    sources['worker/auth.cljs'] = auth

    dispatch = sources['node/dispatch.cljs']
    dispatch = replace_region(dispatch, '(defn handle-node-fetch', '\n  [{:keys [request env registry deps]}]', '(defn- handle-node-fetch-authorized')
    dispatch += '''
(defn handle-node-fetch [{:keys [request] :as opts}]
  (let [gate (js/require "/app/auth/http-gate.cjs")]
    (p/let [allowed? ((aget gate "allowRequest") request)]
      (if allowed?
        (p/let [response (handle-node-fetch-authorized opts)]
          ((aget gate "normalizeResponse") response))
        (js/Response. nil #js {:status 404})))))
'''
    sources['node/dispatch.cljs'] = dispatch

    server = sources['node/server.cljs']
    server = replace_region(server, '(defn- access-allowed?', '(defn- attach-ws!', '''(defn- access-allowed?
  [env graph-id request]
  (p/let [permitted? ((aget (js/require "/app/auth/http-gate.cjs") "allowUpgrade") request)
          claims (when permitted? (auth/auth-claims request env))
          user-id (when claims (aget claims "sub"))
          db (aget env "DB")]
    (if (string? user-id)
      (index/<user-has-access-to-graph? db graph-id user-id)
      false)))

''')
    server = replace_region(server, '(defn- handle-ws-connection', '(defn- local-do-namespace', '''(defn- handle-ws-connection
  [ctx env request ^js socket]
  ;; Check both idle and active sockets. Revocation never deletes graph data.
  (let [check-authorization!
        (fn []
          (-> (auth/auth-claims request env)
              (p/then (fn [claims] (when-not claims (.terminate socket))))
              (p/catch (fn [_] (.terminate socket)))))
        authorization-timer (js/setInterval check-authorization! 1000)]
    (p/let [claims (auth/auth-claims request env)
            user (presence/claims->user claims)]
      (when user
        (presence/add-presence! ctx socket user))
      (presence/broadcast-online-users! ctx))
    (.on socket "message"
         (fn [data]
           (-> (p/let [claims (auth/auth-claims request env)]
                 (if-not claims
                   (.terminate socket)
                   (let [text (if (string? data) data (.toString data))]
                     (try
                       (ws-handler/handle-ws-message! ctx socket text)
                       (catch :default e
                         (log/error :db-sync/ws-error e)
                         (.send socket (js/JSON.stringify #js {:type "error" :message "server error"})))))))
               (p/catch (fn [_] (.terminate socket))))))
    (.on socket "close"
         (fn []
           (js/clearInterval authorization-timer)
           (presence/remove-presence! ctx socket)
           (presence/broadcast-online-users! ctx)
           (detach-ws! ctx socket)))
    (.on socket "error"
         (fn [error]
           (js/clearInterval authorization-timer)
           (presence/remove-presence! ctx socket)
           (presence/broadcast-online-users! ctx)
           (detach-ws! ctx socket)
           (log/error :db-sync/ws-error error)))))

''')
    sources['node/server.cljs'] = server
    for relative, text in sources.items():
        (directory / relative).write_text(HEADER + text)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: patch-source.py LOGSEQ_SOURCE_DIRECTORY')
    patch(Path(sys.argv[1]))
