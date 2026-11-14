# Logseq self-host client and sync server

Run Logseq's native encrypted database sync on your own server. The operator
must issue or import each identity from the local console. There is no account
service, public signup, network admin API, or network MCP endpoint.

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

## Generate a public sync URL

Start the server and its optional Cloudflare tunnel:

```sh
docker compose -f compose.yaml -f compose.public.yaml up -d --build
./scripts/sync-url
```

The tunnel generates an internet-reachable `https://…trycloudflare.com` address.
Paste that address into the client’s sync server URL field, then enter the
operator-issued sync code. No Cloudflare account, domain, inbound port or
Colin-hosted gateway is required. Each operator runs their own server.
The address is public; graph access still requires an explicit console grant.

Cloudflare [Quick Tunnels](https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/)
are temporary and have no uptime guarantee. The address changes when the
tunnel is recreated. Read the new address with `./scripts/sync-url` and update
your clients. For regular use, configure your own stable HTTPS domain below.
The server waits for the tunnel, uses its address for asset links, and restarts
if the tunnel address changes or its readiness lease expires. The URL command
fails while the tunnel is unavailable; it never prints an access code.

Use both Compose files for subsequent `exec`, `logs`, `restart` and `down`
commands. Keep the `sync-data` volume.

## Use a stable server URL

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

Use the matching Logseq Selfhost client. On a fresh install, enter the server
URL and issued LS2 sync code. Existing users can open **Sync → Sync settings…**
to change them. New installations require an explicit server URL and code.
The client does not enroll users or choose Colin’s service for them.

The compact code does not contain a server URL. Enter the same URL and code
on your other devices. HTTP is accepted only for localhost development;
remote URLs require HTTPS. Changing the URL for the same identity preserves
your local profile, offline edits and encryption keys, including after a
temporary tunnel address changes. The client verifies access before saving
the settings and restarts to use the new address.

Older previews have a fixed server URL and need an updated client.
An old client may generate a code locally; that code gets no server access
unless the operator deliberately imports its public subject.

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
See [LICENSING.md](LICENSING.md), [LICENSE](LICENSE), [NOTICE](NOTICE) and
`server/upstream.json` for AGPL-3.0 terms and upstream attribution. When serving
other users, provide the exact corresponding source. Export the source from
your image using `scripts/export-source <container> <output-directory>`,
and provide the bundle privately to authorized users or through your own
source hosting. The sync route allowlist needs no new endpoint.

Cloudflare is optional. `worker.example.mjs` shows the narrow front used for
this protocol. Bind `SYNC_ORIGIN` to your own Cloudflare VPC origin service
and set its internal origin hostname in that example. The standalone origin
enforces the same narrow protocol without Cloudflare or a fleet.

## Client build source

`client/` and `scripts/build-logseq-{selfhost,linux}-client.py` contain the
matching desktop client recipe. It patches hash-checked official Logseq 2.0.2
application archives and retains native Logseq encryption. The Linux build
uses the official pinned x86_64 ZIP; the Mac build requires macOS and the
configured Apple signing identity. A desktop application runs on the user’s
computer; the Compose services host the sync server and its optional tunnel.
A browser application container is not included in this release.

Jenkins owns release builds, signatures and publication. Its trusted controller
is separate from this public source repository. Maintainers set
`LOGSEQ_DELIVERY_CONTROLLER` to that controller’s `delivery/public.py` and use
`scripts/deliver run --phase dependencies|server|tunnel|linux --revision <sha>`.
Observe the returned queue/build handle with `scripts/deliver observe --build <n>`.
The dependency phase prepares an exported cache; it is not a runnable server.
Container publication and compiled client acceptance are recorded separately
in [VALIDATION.md](VALIDATION.md).
