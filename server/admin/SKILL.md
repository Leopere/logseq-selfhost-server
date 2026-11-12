---
name: logseq-sync-admin
description: Issue, list, import, or revoke Logseq sync authorization from the operator's server console only.
---

# Local Logseq sync authorization

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

Use this skill only on the server and only for the operator's deliberate request.
Never expose these commands through HTTP, WebSocket, a public MCP server, or a
remote administration endpoint. No network administration API is provided.

Run as the service account, with the same `LOGSEQ_GRANTS_FILE` and persistent
data directory as the server. Its default registry is `/app/data/grants.json`.
The data directory must exist and must not be writable by other users.

```sh
node /app/auth/logseq-sync-admin.cjs grant 'device or person label'
node /app/auth/logseq-sync-admin.cjs list
node /app/auth/logseq-sync-admin.cjs revoke <id>
```

`grant` returns an ID and a sensitive `syncCode` once. Deliver the code only to
the intended operator/recipient. Never paste it into chat, tickets, logs, Git,
or a shared report. The registry stores the identity, label, creation time,
and revocation time, never the sync code, wrapping key, or E2EE material.
The console process transiently generates the code's wrapping root; it must
run on a trusted operator machine. The sync service does not receive this root.

For migration, first identify the existing subject locally without printing
its sync code. Deliberately authorize that subject, retaining the same code:

```sh
node /app/auth/logseq-sync-admin.cjs import <subject> 'existing devices'
node /app/auth/logseq-sync-admin.cjs import <legacy-owner-subject> 'existing legacy devices' --legacy
```

`--legacy` requires the subject to match `LOGSEQ_OWNER_USER_ID` and the server
must retain its existing HMAC secret configuration. New operators need no
legacy HMAC key. A missing or unreadable registry denies access. A revoked
identity cannot be silently imported again; issue a new code deliberately.

Revocation applies to subsequent authorization checks. This server rechecks
active WebSockets every second and before processing each message, terminating
a socket when its grant is revoked. Signed encrypted asset URLs can remain
valid until their expiry, at most five minutes. Never delete graph data to revoke a grant.

A `.lock` file means another local command may be editing the registry. Do not
remove it unless the operator has established no command still owns it. Never
reset a corrupt registry or replace existing data with an empty file.
