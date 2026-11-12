# Local candidate validation

Copyright (c) 2026 Colin Knapp, https://colinknapp.com

Prepared locally on November 12, 2026. No remote or publication is configured.
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
