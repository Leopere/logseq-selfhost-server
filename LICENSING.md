# Licensing and source inventory

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

The combined sync server and this release's original code are licensed under
**GNU AGPL version 3 (AGPL-3.0-only)**. Colin authorized this open-source release
on November 12, 2026. LICENSE contains the license; NOTICE identifies Colin's
work without claiming upstream copyright. Earlier private notices are not the
license for this release.

## What the server contains

| Component | Source and provenance | License / treatment |
|---|---|---|
| Database sync engine, SQLite index/graph storage, assets, E2EE key-envelope routes, native WS protocol | `logseq/logseq` commit `69da7e2215b336cc5123dafb2a1686996e39596c`, `deps/db-sync` and its shared local Clojure dependencies | Upstream AGPL-3.0; preserve upstream authors, license and notices |
| Source-build container recipe | Adapted from `yshalsager/logseq-selfhost`, commit `ead4eb47db7e98fde39124b77dfd8d269118b406`, `images/sync/Dockerfile` | Upstream AGPL-3.0; adaptations identified separately |
| Owner signature verification, console grants, registry, exact protocol gate, optional Worker, source patches and packaging | Colin's original project files and modifications | Colin can license his contributions; this release uses AGPL-3.0-only |
| Former private wrapper image | `ghcr.io/leopere/cisl2-logseq-sync@sha256:c89c0584b25bbdd6649b02d9e90e3ab5005fd6c7db95e8f7d3e1fb7ad5c67964` | Derived AGPL server, not an independent proprietary implementation; no runtime build dependency remains |
| Former wrapper's upstream image | `ghcr.io/yshalsager/logseq-selfhost-sync@sha256:0b4dad699d60e950f123f9be80905b4e6b6fc8e386a110a387231eb6b97d3a4a` | Packages the pinned Logseq node adapter; replaced by the source build |
| Runtime | Distroless Node.js 24 / Debian, image digest in `server/Dockerfile` | Each upstream component retains its license; system software is not Colin's work |
| Build tools | Debian, mise 2026.10.23, Node 24.10.0, OpenJDK 21.0.2, Clojure CLI 1.12.3.1577, pnpm 10.33.0 | Upstream tool licenses; pinned configuration in `server/mise.toml` |
| JavaScript dependencies | `@cfworker/json-schema`, `@cloudflare/codemode`, `@modelcontextprotocol/sdk`, `@sentry/cloudflare`, `@sentry/node`, `better-sqlite3`, `mldoc`, `shadow-cljs`, `transit-js`, `ws`, `zod` | Exact resolved versions/integrities and transitive graph in upstream `deps/db-sync/pnpm-lock.yaml`; retain package license files, including dependencies unused by the narrow network gate |
| Clojure dependencies | `deps/db-sync/deps.edn` plus `deps/common`, `deps/db`, `deps/outliner` and their dependency files; includes Clojure, Logseq Datascript, Transit, cljs-bean, shadow-cljs, glogi, Reitit | Preserve each upstream license and corresponding source; complete pinned Logseq tree is included in the image |
| Customized desktop client in the private development repository | Logseq 2.0.2 app plus `client/` modifications; original wrapper hashes in `client/base-source.json` | Logseq derivative stays AGPL; Electron and other bundled dependencies retain their licenses; excluded from the server-only public candidate |

The former image's local provenance ledger records wrapper build source
`7493f02cbca316580abb0ed2f5c24b38eac022a4`, upstream wrapper source
`ead4eb47db7e98fde39124b77dfd8d269118b406`, and the unmodified adapter SHA256
`10dbb83e78a8cca17810ec9cb14da1a852ee1d80fa3aa63f96eae7d0ed025206`.
Its overlay replaced two compiled auth functions. The new build patches
reviewed, hash-checked source before compilation instead.

## What Colin can license

Colin can license his own code, writing and modifications. He cannot relicense
Logseq or other authors' work as exclusively his, remove their notices, or
apply a conflicting all-rights-reserved restriction to the combined derivative.
Using AGPL-3.0-only for the whole server is the straightforward compatible
choice. Independent tools could have another compatible license, but this
release uses one license for simplicity. Dependency licenses remain intact.

The basis is the pinned [Logseq license](https://github.com/logseq/logseq/blob/69da7e2215b336cc5123dafb2a1686996e39596c/LICENSE.md),
the [upstream container project's license](https://github.com/yshalsager/logseq-selfhost/blob/ead4eb47db7e98fde39124b77dfd8d269118b406/LICENSE),
and AGPL sections 4–6 and 13 in LICENSE. Copies of the upstream notices are in
`third_party/`. This is the project's licensing conclusion, not a claim that
all transitive dependencies have the same license.

## Corresponding source and operation

`server/upstream.json` pins the public upstream tree. The Dockerfile fetches
that tree, uses its lockfiles, applies `server/patch-source.py`, and includes
the original complete source archive plus patches/build metadata under
`/app/corresponding-source`. The running auth sources are in `/app/auth` and
operator skill in `/app/admin`. Copy those together with the source archive,
Compose file, notices and recipe when offering corresponding source. The
candidate includes a source export command for this purpose.

When distributing the image or allowing other people to interact with a
modified network service, provide the matching complete source and preserve
the AGPL source offer, copyright and warranty notices. Give authorized users
the matching source bundle or a reachable source link outside the sync protocol;
no additional sync/admin endpoint is needed. An unpublished local candidate
is preparation, not public source availability. No repository has been made
public by this task.

Source rebuildability does not promise byte-identical images: Debian package
repositories and tool mirrors remain external inputs. There is no proprietary
CISL2 code, credentials or fleet requirement in the standalone server package.
