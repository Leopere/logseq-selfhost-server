# Local candidate validation

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

Prepared locally on November 12, 2026. At that time no remote or publication was configured.
Six Node authorization/grant/route tests and five Worker contract tests passed.
The candidate is server-only; it contains no graph, backup, runtime grant file,
client installer, private delivery configuration or copied development history.

Gitleaks 8.30.1 tree scan findings were reviewed: source SHA256 fingerprints
and deliberately invalid JWT fixtures only. The committed history is scanned
separately after commit. Pattern scanning cannot prove absence of every secret.
Actual image compilation and live acceptance are tracked separately in the
private development repository; local tests do not establish deployment.

The combined program is AGPL-3.0-only. Supply matching corresponding source
to users of a modified network service and retain upstream notices.

## Public URL work — November 14, 2026

The public repository is `Leopere/logseq-selfhost-server`. Optional generated
HTTPS routing is prepared in `compose.public.yaml`. Local URL validation,
stale-lease and restart checks are separate from an actual tunnel connection.
The external Jenkins controller is tracked in `Leopere/logseq-sync`,
`delivery/public.py`; job `deliver-logseq-public` owns image builds, signatures,
publication and disposable runtime checks. No permanent shared service is
created. Actual build handles and live acceptance will be recorded below.

The matching desktop client recipes are now included. All 32 Node tests and
seven Python tests pass locally, including explicit URL selection, refused
redirects, saved credentials, compiled renderer URL handoff, tunnel lease
expiry, and offline profile continuity through a tunnel URL change.
Independent review confirmed the installed compiled HTTP and WebSocket
builders consume the selected URL. New binary packaging and real public
HTTPS/WSS acceptance have not yet completed.
