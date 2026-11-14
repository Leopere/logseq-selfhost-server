# Logseq self-host sync server

Run Logseq's native encrypted database sync on your own server. The operator
must issue or import each identity from the local console. There is no account
service, public signup, network admin API, or network MCP endpoint.

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

## Public URL setup

See the [root guide](../README.md) for the optional generated HTTPS tunnel
and the stable-domain setup. Read the current generated address with
`./scripts/sync-url` from the repository root. An access code and a server URL
are separate: the URL identifies the operator’s server; the code authorizes
an identity on that server.

## Start the server

Install Docker with Compose. From this source directory:

```sh
export LOGSEQ_PUBLIC_URL=https://sync.example.com
docker compose up -d --build
curl --fail http://localhost:8787/health
```

Put your HTTPS reverse proxy in front of `127.0.0.1:8787` and forward WebSocket
upgrades. Persist the `sync-data` volume. The container runs without root,
with a read-only filesystem except its data volume and temporary directory.
A fresh server authorizes nobody. Never delete its volume to fix access.

## Issue a code deliberately

Run only from the operator's trusted server console. Keep stdout out of logs
and deliver the returned `syncCode` privately to its intended recipient.

```sh
docker compose exec sync /nodejs/bin/node /app/auth/logseq-sync-admin.cjs grant 'my laptop'
docker compose exec sync /nodejs/bin/node /app/auth/logseq-sync-admin.cjs list
docker compose exec sync /nodejs/bin/node /app/auth/logseq-sync-admin.cjs revoke <id>
```

Use a compatible Logseq self-host client, configure your server URL, and paste
the issued LS2 sync code. The compact code does not contain the server URL.
Colin's existing preview client fixes its URL to his service; operators need
a client configured for their own URL. An old client may generate a local
code itself; that code gets no server access unless you deliberately import
its public subject. Client bearer refresh alone never enrolls an identity.

The registry is `/app/data/grants.json`, mode 0600. It stores public IDs,
labels, kind and creation/revocation times. It never stores codes or E2EE
roots. The trusted console transiently creates a root when minting an LS2
code; the HTTP sync process never receives that root. Keep the code safe:
people sharing one code share access and encryption keys. This is an identity
grant, not separate revocation for each device sharing a code.

Revocation blocks new HTTP requests and WS handshakes; active sockets recheck
every second and before processing a message. Previously signed encrypted
asset URLs remain capabilities until their expiry, at most five minutes.
No graph data is deleted. Denied authentication returns an empty 404 or a
dropped direct WS, and only generic local logs. Health and supported native
CORS preflights remain public. This does not try to conceal that an HTTP host
exists or eliminate ordinary network timing differences.

## Keep an existing identity

Back up the complete data volume and grant registry before an upgrade. Import
only public subjects you have deliberately authorized; never pass a code or
root as a shell argument:

```sh
docker compose exec sync /nodejs/bin/node /app/auth/logseq-sync-admin.cjs import <subject> 'existing devices'
```

Legacy HS256 migrations additionally retain the existing signing-key mount
and `LOGSEQ_OWNER_*` configuration and use `import <subject> 'existing devices'
--legacy`. A fresh operator needs none of that legacy configuration. Missing
or damaged grants fail closed. A revoked identity cannot be silently revived;
issue a new code instead. Preserve existing graphs, keys and backups.

An agent running on the server can use `server/admin/SKILL.md` for the same
console commands. There is no network administration surface. No stdio MCP
is needed for this small command interface.

## Source and license

The Dockerfile builds pinned public Logseq source, with hash-checked source
patches and locked dependencies. It does not pull Colin's old private image.
See [LICENSING.md](../LICENSING.md), [LICENSE](../LICENSE), [NOTICE](../NOTICE) and
`server/upstream.json` for AGPL-3.0 terms and upstream attribution. When serving
other users, provide the exact corresponding source. Export the source from
your image using `scripts/export-source <container> <output-directory>`,
and provide the bundle privately to authorized users or through your own
source hosting. The sync route allowlist needs no new endpoint.

Cloudflare is optional. `worker.example.mjs` shows the narrow front used for
this protocol. Bind `SYNC_ORIGIN` to your own Cloudflare VPC origin service
and set its internal origin hostname in that example. The standalone origin
enforces the same narrow protocol without Cloudflare or a fleet.
